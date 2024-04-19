package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/database/postgres"
	"github.com/GosMachine/ServiceAuth/internal/database/redis"
	"github.com/GosMachine/ServiceAuth/internal/models"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Auth struct {
	log                *zap.Logger
	db                 Database
	tokenTTL           time.Duration
	rememberMeTokenTTL time.Duration
	redis              Redis
}

type Database interface {
	CreateUser(email, ip string, passHash []byte, emailVerified bool) error
	User(email string) (models.User, error)
	UpdateUser(user models.User) error
	EmailVerified(email string) (bool, error)
	EmailVerify(email string) error
	// DeleteUser(email string) error
}

type Redis interface {
	CreateToken(email string, expiration time.Duration) string
	GetToken(token string) string
	DeleteToken(token string) error
}

func New(log *zap.Logger, db *postgres.Database, redis *redis.Redis, tokenTTL, rememberMeTokenTTL time.Duration) *Auth {
	return &Auth{
		log:                log,
		db:                 db,
		redis:              redis,
		tokenTTL:           tokenTTL,
		rememberMeTokenTTL: rememberMeTokenTTL,
	}
}

// oauth for google, github, etc.
func (a *Auth) OAuth(email, ip string) (string, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("attempting to OAuth")

	user, err := a.db.User(email)
	if err != nil {
		err = a.db.CreateUser(email, ip, []byte{}, true)
		if err != nil {
			log.Error("failed to create user", zap.Error(err))
			return "", err
		}
	} else {
		user.EmailVerified = true
		if err = a.updateUser(user, ip); err != nil {
			log.Error("failed to update user", zap.Error(err))
			return "", err
		}
	}
	token := a.createToken(email, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}

	log.Info("OAuth successfully")
	return token, nil
}

func (a *Auth) Login(email, password, ip, rememberMe string) (string, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("attempting to login user")

	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("passwords do not match", zap.Error(err))
		return "", ErrInvalidCredentials
	}
	if err = a.updateUser(user, ip); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", err
	}
	token := a.createToken(email, rememberMe)
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}

	log.Info("user logged in successfully")
	return token, nil
}

func (a *Auth) Register(email, pass, ip, rememberMe string) (string, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to generate password hash", zap.Error(err))
		return "", err
	}
	err = a.db.CreateUser(email, ip, passHash, false)
	if err != nil {
		log.Error("failed to create user", zap.Error(err))
		return "", err
	}
	token := a.createToken(email, rememberMe)
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}

	log.Info("user register successfully")
	return token, nil
}

func (a *Auth) Logout(token string) error {
	err := a.redis.DeleteToken(token)
	if err != nil {
		a.log.Error("error delete token", zap.String("token", token))
	}
	return err
}

func (a *Auth) updateUser(user models.User, ip string) error {
	user.LastLoginDate = time.Now()
	if ip != "" {
		user.LastLoginIp = ip
	}
	return a.db.UpdateUser(user)
}

func (a *Auth) createToken(email, rememberMe string) string {
	tokenTTL := a.tokenTTL
	if rememberMe == "on" {
		tokenTTL = a.rememberMeTokenTTL
	}
	return a.redis.CreateToken(email, tokenTTL)
}

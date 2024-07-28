package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/models"
	"github.com/GosMachine/ServiceAuth/internal/storage/database"
	"github.com/GosMachine/ServiceAuth/internal/storage/redis"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Auth struct {
	log                *zap.Logger
	db                 database.Database
	tokenTTL           time.Duration
	rememberMeTokenTTL time.Duration
	redis              redis.Service
}

func New(log *zap.Logger, db database.Database, redis redis.Service, tokenTTL, rememberMeTokenTTL time.Duration) *Auth {
	return &Auth{
		log:                log,
		db:                 db,
		redis:              redis,
		tokenTTL:           tokenTTL,
		rememberMeTokenTTL: rememberMeTokenTTL,
	}
}

// oauth for google, github, etc.
func (a *Auth) OAuth(email, ip string) (string, time.Duration, error) {
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
			return "", 0, err
		}
	} else {
		user.EmailVerified = true
		if err = a.updateUser(user, ip); err != nil {
			log.Error("failed to update user", zap.Error(err))
			return "", 0, err
		}
	}
	token, tokenTTL := a.createToken(email, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", 0, fmt.Errorf("failed to generate token")
	}

	log.Info("OAuth successfully")
	return token, tokenTTL, nil
}

func (a *Auth) Login(email, password, ip, rememberMe string) (string, time.Duration, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("attempting to login user")

	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", 0, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("passwords do not match", zap.Error(err))
		return "", 0, ErrInvalidCredentials
	}
	if err = a.updateUser(user, ip); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", 0, err
	}
	token, tokenTTL := a.createToken(email, rememberMe)
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", 0, fmt.Errorf("failed to generate token")
	}

	log.Info("user logged in successfully")
	return token, tokenTTL, nil
}

func (a *Auth) Register(email, pass, ip, rememberMe string) (string, time.Duration, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to generate password hash", zap.Error(err))
		return "", 0, err
	}
	err = a.db.CreateUser(email, ip, passHash, false)
	if err != nil {
		log.Error("failed to create user", zap.Error(err))
		return "", 0, err
	}
	token, tokenTTL := a.createToken(email, rememberMe)
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", 0, fmt.Errorf("failed to generate token")
	}

	log.Info("user register successfully")
	return token, tokenTTL, nil
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

func (a *Auth) createToken(email, rememberMe string) (string, time.Duration) {
	tokenTTL := a.tokenTTL
	if rememberMe == "on" {
		tokenTTL = a.rememberMeTokenTTL
	}
	return a.redis.CreateToken(email, tokenTTL), tokenTTL
}

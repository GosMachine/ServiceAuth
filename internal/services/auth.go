package auth

import (
	"errors"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/database/postgres"
	"github.com/GosMachine/ServiceAuth/internal/models"
	"github.com/GosMachine/ServiceAuth/internal/pkg/jwt"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Auth struct {
	log      *zap.Logger
	db       Database
	tokenTTL time.Duration
}

type Database interface {
	CreateUser(email, ip string, passHash []byte, emailVerified bool) error
	User(email string) (models.User, error)
	UpdateUser(user models.User) error
	EmailVerified(email string) (bool, error)
	// DeleteUser(email string) error
}

func New(log *zap.Logger, db *postgres.Database, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:      log,
		db:       db,
		tokenTTL: tokenTTL,
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

	token, err := jwt.NewToken(email, "on", a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", zap.Error(err))
		return "", err
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
	token, err := jwt.NewToken(email, rememberMe, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", zap.Error(err))
		return "", err
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
	token, err := jwt.NewToken(email, rememberMe, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", zap.Error(err))
		return "", err
	}

	log.Info("user register successfully")
	return token, nil
}

func (a *Auth) EmailVerified(email string) (bool, error) {
	return a.db.EmailVerified(email)
}

// func (a *Auth) Delete() {}

func (a *Auth) updateUser(user models.User, ip string) error {
	user.LastLoginDate = time.Now()
	user.LastLoginIp = ip
	return a.db.UpdateUser(user)
}

package auth

import (
	"ServiceAuth/internal/domain/models"
	"ServiceAuth/internal/storage"
	"ServiceAuth/internal/storage/postgres"
	"ServiceAuth/pkg/jwt"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Auth struct {
	log      *zap.Logger
	db       Storage
	tokenTTL time.Duration
}

type Storage interface {
	SaveUser(email, ip string, passHash []byte) (user models.User, err error)
	User(email string) (models.User, error)
	UpdateUser(user models.User) error
}

func New(log *zap.Logger,
	db *postgres.Storage,
	tokenTTL time.Duration,

) *Auth {
	return &Auth{
		log:      log,
		db:       db,
		tokenTTL: tokenTTL,
	}
}

func (a *Auth) Login(email, password, ip, rememberMe string) (string, error) {
	const op = "Auth.Login"

	log := a.log.With(
		zap.String("op", op),
		zap.String("email", email),
		zap.String("ip", ip),
	)

	log.Info("attempting to login user")

	user, err := a.db.User(email)
	if err != nil {
		a.log.Error("failed to get user", zap.Error(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", zap.Error(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	token, err := jwt.NewToken(email, rememberMe, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", zap.Error(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}
	go func(user models.User, ip string) {
		user.LastLoginDate = time.Now()
		user.LastLoginIp = ip
		err = a.db.UpdateUser(user)
		if err != nil {
			a.log.Error("failed to update user", zap.Error(err))
		}
		log.Info("user logged in successfully")
	}(user, ip)

	return token, nil
}

// RegisterNewUser registers new user in the system and returns user ID.
// If user with given username already exists, returns error.
func (a *Auth) RegisterNewUser(email, pass, ip, rememberMe string) (string, error) {
	const op = "Auth.RegisterNewUser"

	log := a.log.With(
		zap.String("op", op),
		zap.String("email", email),
		zap.String("ip", ip),
	)

	log.Info("registering user")
	_, err := a.db.User(email)
	if err == nil {
		a.log.Error("failed to register user", zap.Error(err))

		return "", fmt.Errorf("%s: %w", op, storage.ErrUserExists)
	}
	token, err := jwt.NewToken(email, rememberMe, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", zap.Error(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}
	go func(pass, email, ip string) {
		passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
		if err != nil {
			log.Error("failed to generate password hash", zap.Error(err))
		}
		_, err = a.db.SaveUser(email, ip, passHash)
		if err != nil {
			log.Error("failed to save user", zap.Error(err))
		}
		log.Info("user register successfully")
	}(pass, email, ip)
	return token, nil
}

type User struct {
	Balance float64
	IsAdmin bool
}

func (a *Auth) User(email string) *User {
	const op = "Auth.User"

	log := a.log.With(
		zap.String("op", op),
		zap.String("email", email),
	)

	log.Info("Getting user")

	user, err := a.db.User(email)
	if err != nil {
		a.log.Error("error getting user")
		return nil
	}

	return &User{Balance: user.Balance, IsAdmin: user.IsAdmin}
}

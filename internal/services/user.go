package auth

import (
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (a *Auth) EmailVerified(email string) (bool, error) {
	verified, err := a.db.EmailVerified(email)
	if err != nil {
		a.log.Error("error email verified check", zap.Error(err))
	}
	return verified, err
}

func (a *Auth) EmailVerify(email string) error {
	err := a.db.EmailVerify(email)
	if err != nil {
		a.log.Error("error email verify", zap.Error(err))
	}
	return err
}

func (a *Auth) ChangePass(email, pass, ip, oldToken string) (string, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("password changing")
	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", ErrInvalidCredentials
	}
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to generate password hash", zap.Error(err))
		return "", err
	}
	user.PassHash = passHash
	if err = a.updateUser(user, ip); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", err
	}
	token := a.createToken(email, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}
	err = a.redis.DeleteToken(oldToken)
	if err != nil {
		log.Error("error delete token", zap.Error(err))
	}

	return token, nil
}

func (a *Auth) ChangeEmail(email, newEmail, oldToken string) (string, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("newEmail", newEmail),
	)
	log.Info("email changing")
	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", ErrInvalidCredentials
	}
	user.Email = newEmail
	if err = a.updateUser(user, ""); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", err
	}
	token := a.createToken(newEmail, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", fmt.Errorf("failed to generate token")
	}
	err = a.redis.DeleteToken(oldToken)
	if err != nil {
		log.Error("error delete token", zap.Error(err))
	}

	return token, nil
}

// func (a *Auth) Delete() {}

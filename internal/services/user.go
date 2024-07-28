package auth

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

func (a *Auth) EmailVerified(email string) (bool, error) {
	verified, err := a.redis.GetEmailVerifiedCache(email)
	if err != nil {
		a.log.Error("error email verified check", zap.Error(err))
	}
	return verified, err
}

func (a *Auth) CreateToken(email, remember string) (string, time.Duration) {
	token, tokenTTL := a.createToken(email, remember)
	a.log.Info("token ttl successfully taken", zap.String("token", token), zap.Duration("tokenTTL", tokenTTL))
	return token, tokenTTL
}

func (a *Auth) GetUserEmail(token string) string {
	if token == "" {
		return ""
	}
	email := a.redis.GetEmail(token)
	a.log.Info("user email successfully taken", zap.String("token", token), zap.String("email", email))
	return email
}

func (a *Auth) EmailVerify(email string) error {
	err := a.db.EmailVerify(email)
	if err != nil {
		a.log.Error("error email verify", zap.Error(err), zap.String("email", email))
		return err
	}
	err = a.redis.SetEmailVerifiedCache(email, true)
	if err != nil {
		a.log.Error("error set email verified", zap.Error(err), zap.String("email", email))
		return err
	}
	return nil
}

func (a *Auth) ChangePass(email, pass, ip, oldToken string) (string, time.Duration, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("ip", ip),
	)
	log.Info("password changing")
	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", 0, ErrInvalidCredentials
	}
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		log.Error("failed to generate password hash", zap.Error(err))
		return "", 0, err
	}
	user.PassHash = passHash
	if err = a.updateUser(user, ip); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", 0, err
	}
	token, tokenTTL := a.createToken(email, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", 0, fmt.Errorf("failed to generate token")
	}
	err = a.redis.DeleteToken(oldToken)
	if err != nil {
		log.Error("error delete token", zap.Error(err))
	}

	return token, tokenTTL, nil
}

func (a *Auth) ChangeEmail(email, newEmail, oldToken string) (string, time.Duration, error) {
	log := a.log.With(
		zap.String("email", email),
		zap.String("newEmail", newEmail),
	)
	log.Info("email changing")
	user, err := a.db.User(email)
	if err != nil {
		log.Error("failed to get user", zap.Error(err))
		return "", 0, ErrInvalidCredentials
	}
	user.Email = newEmail
	if err = a.updateUser(user, ""); err != nil {
		log.Error("failed to update user", zap.Error(err))
		return "", 0, err
	}
	token, tokenTTL := a.createToken(newEmail, "on")
	if token == "" {
		log.Error("failed to generate token", zap.Error(err))
		return "", 0, fmt.Errorf("failed to generate token")
	}
	err = a.redis.DeleteToken(oldToken)
	if err != nil {
		log.Error("error delete token", zap.Error(err))
	}

	err = a.redis.Delete("emailVerified:" + email)
	if err != nil {
		log.Error("error delete email verified", zap.Error(err))
	}

	return token, tokenTTL, nil
}

// func (a *Auth) Delete() {}

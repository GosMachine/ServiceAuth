package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/utils"
	"go.uber.org/zap"
)

// returning user email
func (r *Redis) GetEmail(token string) string {
	return r.client.Get(context.Background(), token).Val()
}

func (r *Redis) CreateToken(email string, expiration time.Duration) string {
	for i := 0; i < 5; i++ {
		token := utils.GenerateRandomString(32)
		if r.client.Exists(context.Background(), token).Val() == 0 {
			if r.client.Set(context.Background(), token, email, expiration).Err() != nil {
				continue
			}
			return token
		}
	}
	return ""
}

func (r *Redis) DeleteToken(token string) error {
	return r.client.Del(context.Background(), token).Err()
}

func (r *Redis) SetEmailVerifiedCache(email string, verified bool) error {
	return r.client.Set(context.Background(), fmt.Sprintf("emailVerified:%s", email), verified, time.Hour*24).Err()
}

func (r *Redis) GetEmailVerifiedCache(email string) (bool, error) {
	verified, err := r.client.Get(context.Background(), fmt.Sprintf("emailVerified:%s", email)).Bool()
	if err != nil {
		r.log.Error("error get user data from cache", zap.Error(err))
		verified, err = r.db.EmailVerified(email)
		if err != nil {
			r.log.Error("err check email verified", zap.String("email", email), zap.Error(err))
			return false, err
		}
		err = r.SetEmailVerifiedCache(email, verified)
		if err != nil {
			r.log.Error("err set email verified cache", zap.Error(err), zap.String("email", email))
		}
		r.log.Info("emailVerified from db", zap.String("email", email))
		return verified, nil
	}
	r.log.Info("emailVerified from cache", zap.String("email", email))
	return verified, nil
}

func (r *Redis) GetTokenTTL(token string) time.Duration {
	return r.client.TTL(context.Background(), token).Val()
}

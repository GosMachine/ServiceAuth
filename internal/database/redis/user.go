package redis

import (
	"context"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/utils"
)

// returning user email
func (r *Redis) GetToken(token string) string {
	return r.Client.Get(context.Background(), token).Val()
}

func (r *Redis) CreateToken(email string, expiration time.Duration) string {
	token := utils.GenerateRandomString(32)
	for i := 0; i < 5; i++ {
		if r.Client.Exists(context.Background(), token).Val() == 0 {
			if r.Client.Set(context.Background(), token, email, expiration).Err() != nil {
				continue
			}
			return token
		}
	}
	return ""
}

func (r *Redis) DeleteToken(token string) error {
	return r.Client.Del(context.Background(), token).Err()
}

func (r *Redis) SetEmailVerifiedCache(email string, value bool) error {
	r.Client.Set(r.Ctx, "emailVerified:"+email, value, time.Hour*24)
	return nil
}

func (r *Redis) GetEmailVerifiedCache(email string) (bool, error) {
	verified, err := r.Client.Get(r.Ctx, "emailVerified:"+email).Bool()
	if err != nil {
		r.Log.Error("error get user data from cache", zap.Error(err))
		verified, err = r.AuthClient.EmailVerified(context.Background(), email)
		r.SetEmailVerifiedCache(email, verified)
		return verified, err
	}
	r.Log.Info("emailVerified from cache", zap.String("email", email))
	return verified, nil
}

func (r *Redis) GetToken(token string) string {
	return r.Client.Get(context.Background(), token).Val()
}

func (r *Redis) DeleteToken(token string) error {
	return r.Client.Del(context.Background(), token).Err()
}

func (r *Redis) GetTokenTTL(token string) time.Duration {
	return r.Client.TTL(context.Background(), token).Val()
}

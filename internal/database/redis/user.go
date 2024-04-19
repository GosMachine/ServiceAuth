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

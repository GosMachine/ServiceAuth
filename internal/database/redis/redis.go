package redis

import (
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	Client *redis.Client
}

func New() *Redis {
	client := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})
	return &Redis{Client: client}
}

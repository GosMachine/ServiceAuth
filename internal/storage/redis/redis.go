package redis

import (
	"os"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/storage/database"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Redis struct {
	client *redis.Client
	db     database.Database
	log    *zap.Logger
}
type Service interface {
	GetEmail(token string) string
	CreateToken(email string, expiration time.Duration) string
	DeleteToken(token string) error
	SetEmailVerifiedCache(email string, verified bool) error
	GetEmailVerifiedCache(email string) (bool, error)
	GetTokenTTL(token string) time.Duration
}

func New(db database.Database, log *zap.Logger) Service {
	client := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASS"),
		DB:       0,
	})
	return &Redis{client: client, db: db, log: log}
}

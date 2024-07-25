package app

import (
	"os"
	"time"

	grpcapp "github.com/GosMachine/ServiceAuth/internal/app/grpc"
	auth "github.com/GosMachine/ServiceAuth/internal/services"
	"github.com/GosMachine/ServiceAuth/internal/storage/database"
	"github.com/GosMachine/ServiceAuth/internal/storage/redis"
	"go.uber.org/zap"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *zap.Logger, tokenTTL, RememberMeTokenTTL time.Duration) *App {
	db, err := database.New()
	if err != nil {
		panic(err)
	}
	redis := redis.New(db, log)
	authService := auth.New(log, db, redis, tokenTTL, RememberMeTokenTTL)
	grpcApp := grpcapp.New(log, authService, os.Getenv("AUTH_SERVICE_ADDR"))
	return &App{
		GRPCSrv: grpcApp,
	}
}

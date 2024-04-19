package app

import (
	"time"

	grpcapp "github.com/GosMachine/ServiceAuth/internal/app/grpc"
	"github.com/GosMachine/ServiceAuth/internal/database/postgres"
	"github.com/GosMachine/ServiceAuth/internal/database/redis"
	auth "github.com/GosMachine/ServiceAuth/internal/services"
	"go.uber.org/zap"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *zap.Logger, grpcPort int, tokenTTL, RememberMeTokenTTL time.Duration) *App {
	db, err := postgres.New()
	if err != nil {
		panic(err)
	}
	redis := redis.New()
	authService := auth.New(log, db, redis, tokenTTL, RememberMeTokenTTL)
	grpcApp := grpcapp.New(log, authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}

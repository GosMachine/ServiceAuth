package app

import (
	grpcapp "ServiceAuth/internal/app/grpc"
	auth "ServiceAuth/internal/services"
	"ServiceAuth/internal/storage/postgres"
	"go.uber.org/zap"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *zap.Logger, grpcPort int, tokenTTL time.Duration) *App {
	db, err := postgres.New()
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, db, tokenTTL)
	grpcApp := grpcapp.New(log, authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}
}

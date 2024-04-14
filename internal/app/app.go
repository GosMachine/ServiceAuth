package app

import (
	grpcapp "github.com/GosMachine/ServiceAuth/internal/app/grpc"
	"github.com/GosMachine/ServiceAuth/internal/database/postgres"
	auth "github.com/GosMachine/ServiceAuth/internal/services"
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

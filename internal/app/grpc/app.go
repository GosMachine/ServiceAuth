package grpcapp

import (
	"fmt"
	grpcauth "github.com/GosMachine/ServiceAuth/internal/grpc/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

type App struct {
	log        *zap.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *zap.Logger, authService grpcauth.Auth, port int) *App {
	gRPCServer := grpc.NewServer()
	grpcauth.RegisterAuthServer(gRPCServer, authService)
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	log := a.log.With(zap.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return err
	}
	log.Info("gRPC server is running", zap.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return err
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"
	a.log.With(zap.String("op", op)).Info("stopping gRPC server", zap.Int("Port", a.port))
	a.gRPCServer.GracefulStop()
}

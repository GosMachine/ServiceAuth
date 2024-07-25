package grpcapp

import (
	grpcauth "github.com/GosMachine/ServiceAuth/internal/grpc/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
)

type App struct {
	log        *zap.Logger
	gRPCServer *grpc.Server
	addr       string
}

func New(log *zap.Logger, authService grpcauth.Auth, addr string) *App {
	gRPCServer := grpc.NewServer()
	grpcauth.RegisterAuthServer(gRPCServer, authService)
	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		addr:       addr,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	log := a.log.With(zap.String("addr", a.addr))

	l, err := net.Listen("tcp", a.addr)
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
	a.log.With(zap.String("op", op)).Info("stopping gRPC server", zap.String("addr", a.addr))
	a.gRPCServer.GracefulStop()
}

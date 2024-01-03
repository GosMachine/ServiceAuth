package main

import (
	"github.com/GosMachine/ServiceAuth/internal/app"
	"github.com/GosMachine/ServiceAuth/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)
	log.Info("starting application", zap.Any("config", cfg))

	application := app.New(log, cfg.GRPC.Port, cfg.TokenTtl)

	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("stopping application", zap.String("signal", sign.String()))
	application.GRPCSrv.Stop()
	log.Info("application stopped")
}

func setupLogger(env string) *zap.Logger {
	level := zap.NewAtomicLevelAt(zapcore.DebugLevel)
	outputPaths := []string{"stdout"}
	if env == "prod" {
		outputPaths = []string{"logs/logfile.txt"}
		level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}
	cfg := zap.Config{
		Encoding:          "json",
		DisableStacktrace: true,
		Level:             level,
		OutputPaths:       outputPaths,
		EncoderConfig:     zap.NewProductionEncoderConfig(),
	}
	logger, _ := cfg.Build()
	defer logger.Sync()
	return logger
}

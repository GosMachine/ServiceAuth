package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/app"
	"github.com/GosMachine/ServiceAuth/internal/config"
	_ "github.com/joho/godotenv/autoload"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger()
	log.Info("starting application", zap.Any("config", cfg))

	application := app.New(log, cfg.TokenTtl, cfg.RememberMeTokenTTL)

	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	log.Info("stopping application", zap.String("signal", sign.String()))
	application.GRPCSrv.Stop()
	log.Info("application stopped")
}

func setupLogger() *zap.Logger {
	cfg := zap.Config{
		Encoding:          "json",
		DisableStacktrace: true,
		Level:             zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths:       []string{"stdout"},
		EncoderConfig:     zap.NewProductionEncoderConfig(),
	}
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05"))
	}
	logger, _ := cfg.Build()
	defer logger.Sync()
	return logger
}

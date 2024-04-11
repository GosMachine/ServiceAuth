package config

import (
	// "github.com/ilyakaznacheev/cleanenv"
	// "os"
	"time"
)

type Config struct {
	Env      string        `yaml:"env" env-default:"local"`
	TokenTtl time.Duration `yaml:"token_ttl" env-required:"true"`
	GRPC     GRPCConfig    `yaml:"grpc"`
}

type GRPCConfig struct {
	Port    int
	Timeout time.Duration `yaml:"timeout"`
}

func MustLoad() *Config {
	// path := os.Getenv("CONFIG_PATH")
	// if path == "" {
	// 	panic("config path is empty")
	// }
	// if _, err := os.Stat(path); os.IsNotExist(err) {
	// 	panic("config file does not exist " + path)
	// }
	// var cfg Config

	// if err := cleanenv.ReadConfig(path, &cfg); err != nil {
	// 	panic("failed to read config" + err.Error())
	// }
	cfg := Config{
		GRPC: GRPCConfig{
			Port:    44043,
			Timeout: 3 * time.Second,
		},
		TokenTtl: 24 * time.Hour,
	}
	return &cfg
}

package config

import (
	"errors"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Configuration struct {
	ForwardedPrefix string        `mapstructure:"forwarded_prefix"`
	SessionSecret   string        `mapstructure:"session_secret"`
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

func GatherConfig() (Configuration, error) {
	// declare default values
	viper.SetDefault("forwarded_prefix", "/")
	viper.SetDefault("cleanup_interval", time.Hour)

	// environment variable bindings
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	var config Configuration
	if err := viper.Unmarshal(&config); err != nil {
		return config, err
	}

	if !strings.HasPrefix(config.ForwardedPrefix, "/") {
		return config, errors.New("forwarded_prefix must start with /")
	}

	if !strings.HasSuffix(config.ForwardedPrefix, "/") {
		config.ForwardedPrefix += "/"
	}

	return config, nil
}

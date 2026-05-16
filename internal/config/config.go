package config

import (
	"context"
	"os"
	"strings"

	"github.com/Kaese72/authentication/internal/logging"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Port     int    `json:"port" mapstructure:"port"`
	User     string `json:"user" mapstructure:"user"`
	Password string `json:"password" mapstructure:"password"`
	Database string `json:"database" mapstructure:"database"`
}

func (conf DatabaseConfig) Validate() error {
	if conf.Host == "" {
		return errors.New("must supply database host")
	}
	return nil
}

type AuthConfig struct {
	RSAPrivateKeyPath      string `json:"rsa-private-key-path" mapstructure:"rsa-private-key-path"`
	RefreshSecret          string `json:"refresh-secret" mapstructure:"refresh-secret"`
	UseTokenExpiryMinutes  int    `json:"use-token-expiry-minutes" mapstructure:"use-token-expiry-minutes"`
	RefreshTokenExpiryDays int    `json:"refresh-token-expiry-days" mapstructure:"refresh-token-expiry-days"`
}

func (conf AuthConfig) Validate() error {
	if conf.RSAPrivateKeyPath == "" {
		return errors.New("must supply auth rsa-private-key-path")
	}
	if conf.RefreshSecret == "" {
		return errors.New("must supply auth refresh-secret")
	}
	return nil
}

type Config struct {
	Database DatabaseConfig `json:"database" mapstructure:"database"`
	Auth     AuthConfig     `json:"auth" mapstructure:"auth"`
}

func (conf Config) Validate() error {
	if err := conf.Database.Validate(); err != nil {
		return err
	}
	if err := conf.Auth.Validate(); err != nil {
		return err
	}
	return nil
}

var Loaded Config

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.database", "authentication")

	viper.BindEnv("auth.rsa-private-key-path")
	viper.BindEnv("auth.refresh-secret")
	viper.BindEnv("auth.use-token-expiry-minutes")
	viper.SetDefault("auth.use-token-expiry-minutes", 10)
	viper.BindEnv("auth.refresh-token-expiry-days")
	viper.SetDefault("auth.refresh-token-expiry-days", 7)

	viper.BindEnv("logging.stdout")
	viper.SetDefault("logging.stdout", true)
	viper.BindEnv("logging.http.url")

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}
}

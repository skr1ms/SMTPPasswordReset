package config

import (
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerConfig    ServerConfig
	DatabaseConfig  DatabaseConfig
	AuthConfig      AuthConfig
	SMTPConfig      SMTPConfig
	RecaptchaConfig RecaptchaConfig
}

type ServerConfig struct {
	Port        string
	FrontendURL string
}

type DatabaseConfig struct {
	URL string
}

type AuthConfig struct {
	AccessTokenSecret     string
	RefreshTokenSecret    string
	PasswordResetTokenTTL time.Duration
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	SSL      bool
}

type RecaptchaConfig struct {
	SecretKey   string
	SiteKey     string
	Environment string
}

func NewConfig() *Config {
	_ = godotenv.Load()

	return &Config{
		ServerConfig: ServerConfig{
			Port:        getEnv("SERVER_PORT", "3000"),
			FrontendURL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
		DatabaseConfig: DatabaseConfig{
			URL: getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/postgres"),
		},
		AuthConfig: AuthConfig{
			AccessTokenSecret:     getEnv("ACCESS_TOKEN_SECRET", "default_access_secret"),
			RefreshTokenSecret:    getEnv("REFRESH_TOKEN_SECRET", "default_refresh_secret"),
			PasswordResetTokenTTL: 1 * time.Hour,
		},
		SMTPConfig: SMTPConfig{
			Host:     getEnv("SMTP_HOST", "smtp.yandex.com"),
			Port:     getEnvAsInt("SMTP_PORT", 465),
			Username: getEnv("SMTP_USERNAME", "ResetPassword@doyoupaint.com"),
			Password: getEnv("SMTP_PASSWORD", "gprcnfxfvxnlzcbm"),
			From:     getEnv("SMTP_FROM", "ResetPassword@doyoupaint.com"),
			SSL:      getEnvAsBool("SMTP_SSL", true),
		},
		RecaptchaConfig: RecaptchaConfig{
			SecretKey:   getEnv("RECAPTCHA_SECRET_KEY", "default_recaptcha_secret"),
			SiteKey:     getEnv("RECAPTCHA_SITE_KEY", "default_recaptcha_site"),
			Environment: getEnv("ENVIRONMENT", "development"),
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

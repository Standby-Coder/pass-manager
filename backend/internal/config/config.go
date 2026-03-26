package config

import "os"

type Config struct {
	Host         string
	Port         string
	DatabasePath string
	JWTSecret    string
}

func Load() Config {
	return Config{
		Host:         getEnv("APP_HOST", "0.0.0.0"),
		Port:         getEnv("APP_PORT", "8080"),
		DatabasePath: getEnv("DATABASE_PATH", "data/pass-manager.db"),
		JWTSecret:    getEnv("JWT_SECRET", "change-me"),
	}
}

func (c Config) ServerAddress() string {
	return c.Host + ":" + c.Port
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}

	return fallback
}
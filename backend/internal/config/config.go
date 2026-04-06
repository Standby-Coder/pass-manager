package config

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"pass-manager/backend/internal/models"

	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type SecurityConfig struct {
	MinPasswordLength  int           `json:"min_password_length"`
	RequireUppercase   bool          `json:"require_uppercase"`
	RequireLowercase   bool          `json:"require_lowercase"`
	RequireDigit       bool          `json:"require_digit"`
	RequireSpecialChar bool          `json:"require_special_char"`
	MaxFailedAttempts  int           `json:"max_failed_attempts"`
	LockoutDuration    time.Duration `json:"lockout_duration"`
	TokenExpiry        time.Duration `json:"token_expiry"`
	InactivityTimeout  time.Duration `json:"inactivity_timeout"`
}

type Config struct {
	Host            string
	Port            string
	DatabasePath    string
	JWTSecret       string
	AllowedOrigins  string
	EncryptionKey   string
	DBEncryptionKey string
	AdminEmail      string
	Security        SecurityConfig
}

// InitViper sets defaults, binds env vars, and reads config file.
func InitViper(cfgFile string) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./data")
	}

	// Defaults
	viper.SetDefault("host", "0.0.0.0")
	viper.SetDefault("port", "8080")
	viper.SetDefault("database_path", "data/pass-manager.db")
	viper.SetDefault("jwt_secret", "change-me")
	viper.SetDefault("allowed_origins", "http://127.0.0.1:5173")
	viper.SetDefault("encryption_key", "")
	viper.SetDefault("db_encryption_key", "")
	viper.SetDefault("admin_email", "")

	viper.SetDefault("security.min_password_length", 8)
	viper.SetDefault("security.require_uppercase", true)
	viper.SetDefault("security.require_lowercase", true)
	viper.SetDefault("security.require_digit", true)
	viper.SetDefault("security.require_special_char", true)
	viper.SetDefault("security.max_failed_attempts", 5)
	viper.SetDefault("security.lockout_duration", "15m")
	viper.SetDefault("security.token_expiry", "1h")
	viper.SetDefault("security.inactivity_timeout", "15m")

	// Bind env vars (backward compatible with Phase 2 env var names)
	viper.AutomaticEnv()

	viper.BindEnv("host", "APP_HOST")
	viper.BindEnv("port", "APP_PORT")
	viper.BindEnv("database_path", "DATABASE_PATH")
	viper.BindEnv("jwt_secret", "JWT_SECRET")
	viper.BindEnv("allowed_origins", "ALLOWED_ORIGINS")
	viper.BindEnv("encryption_key", "ENCRYPTION_KEY")
	viper.BindEnv("db_encryption_key", "DB_ENCRYPTION_KEY")
	viper.BindEnv("admin_email", "ADMIN_EMAIL")

	viper.BindEnv("security.min_password_length", "MIN_PASSWORD_LENGTH")
	viper.BindEnv("security.require_uppercase", "REQUIRE_UPPERCASE")
	viper.BindEnv("security.require_lowercase", "REQUIRE_LOWERCASE")
	viper.BindEnv("security.require_digit", "REQUIRE_DIGIT")
	viper.BindEnv("security.require_special_char", "REQUIRE_SPECIAL_CHAR")
	viper.BindEnv("security.max_failed_attempts", "MAX_FAILED_ATTEMPTS")
	viper.BindEnv("security.lockout_duration", "LOCKOUT_DURATION")
	viper.BindEnv("security.token_expiry", "TOKEN_EXPIRY")
	viper.BindEnv("security.inactivity_timeout", "INACTIVITY_TIMEOUT")

	_ = viper.ReadInConfig() // config file is optional
}

// Load reads the current Viper values into a Config struct.
func Load() Config {
	return Config{
		Host:            viper.GetString("host"),
		Port:            viper.GetString("port"),
		DatabasePath:    viper.GetString("database_path"),
		JWTSecret:       viper.GetString("jwt_secret"),
		AllowedOrigins:  viper.GetString("allowed_origins"),
		EncryptionKey:   viper.GetString("encryption_key"),
		DBEncryptionKey: viper.GetString("db_encryption_key"),
		AdminEmail:      viper.GetString("admin_email"),
		Security: SecurityConfig{
			MinPasswordLength:  viper.GetInt("security.min_password_length"),
			RequireUppercase:   viper.GetBool("security.require_uppercase"),
			RequireLowercase:   viper.GetBool("security.require_lowercase"),
			RequireDigit:       viper.GetBool("security.require_digit"),
			RequireSpecialChar: viper.GetBool("security.require_special_char"),
			MaxFailedAttempts:  viper.GetInt("security.max_failed_attempts"),
			LockoutDuration:    parseDuration(viper.GetString("security.lockout_duration"), 15*time.Minute),
			TokenExpiry:        parseDuration(viper.GetString("security.token_expiry"), 1*time.Hour),
			InactivityTimeout:  parseDuration(viper.GetString("security.inactivity_timeout"), 15*time.Minute),
		},
	}
}

func (c Config) ServerAddress() string {
	return c.Host + ":" + c.Port
}

// WarnInsecureDefaults logs a warning if security-sensitive config values are still set to defaults.
func (c Config) WarnInsecureDefaults() {
	if c.JWTSecret == "change-me" {
		log.Println("WARNING: JWT_SECRET is set to the default value. Set a strong secret in production.")
	}
}

// GetSecurityFromDB reads admin-configured overrides from the app_settings table.
func GetSecurityFromDB(db *gorm.DB, defaults SecurityConfig) SecurityConfig {
	var settings []models.AppSetting
	if err := db.Find(&settings).Error; err != nil {
		return defaults
	}

	m := make(map[string]string)
	for _, s := range settings {
		m[s.Key] = s.Value
	}

	cfg := defaults
	if v, ok := m["min_password_length"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MinPasswordLength = n
		}
	}
	if v, ok := m["require_uppercase"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RequireUppercase = b
		}
	}
	if v, ok := m["require_lowercase"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RequireLowercase = b
		}
	}
	if v, ok := m["require_digit"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RequireDigit = b
		}
	}
	if v, ok := m["require_special_char"]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.RequireSpecialChar = b
		}
	}
	if v, ok := m["max_failed_attempts"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxFailedAttempts = n
		}
	}
	if v, ok := m["lockout_duration"]; ok {
		cfg.LockoutDuration = parseDuration(v, defaults.LockoutDuration)
	}
	if v, ok := m["token_expiry"]; ok {
		cfg.TokenExpiry = parseDuration(v, defaults.TokenExpiry)
	}
	if v, ok := m["inactivity_timeout"]; ok {
		cfg.InactivityTimeout = parseDuration(v, defaults.InactivityTimeout)
	}

	return cfg
}

// SecuritySettingsToMap converts a SecurityConfig to a map for API responses.
func SecuritySettingsToMap(sec SecurityConfig) map[string]string {
	return map[string]string{
		"min_password_length":  fmt.Sprint(sec.MinPasswordLength),
		"require_uppercase":    fmt.Sprint(sec.RequireUppercase),
		"require_lowercase":    fmt.Sprint(sec.RequireLowercase),
		"require_digit":        fmt.Sprint(sec.RequireDigit),
		"require_special_char": fmt.Sprint(sec.RequireSpecialChar),
		"max_failed_attempts":  fmt.Sprint(sec.MaxFailedAttempts),
		"lockout_duration":     sec.LockoutDuration.String(),
		"token_expiry":         sec.TokenExpiry.String(),
		"inactivity_timeout":   sec.InactivityTimeout.String(),
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

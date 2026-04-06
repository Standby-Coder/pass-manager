package router

import (
	"log"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/handlers"
	"pass-manager/backend/internal/middleware"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Setup(db *gorm.DB, cfg config.Config) *gin.Engine {
	r := gin.Default()
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORS(cfg.AllowedOrigins))

	// Create field encryptor
	enc, err := crypto.NewFieldEncryptor(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize field encryptor: %v", err)
	}

	healthHandler := handlers.NewHealthHandler(db)
	r.GET("/health", healthHandler.GetHealth)

	authHandler := handlers.NewAuthHandler(db, cfg)
	auth := r.Group("/api/auth")
	{
		auth.POST("/register", authHandler.Register)
		auth.POST("/login", authHandler.Login)
		auth.POST("/mfa/verify", authHandler.VerifyMFA)
		auth.POST("/password-reset/request", authHandler.RequestPasswordReset)
		auth.POST("/password-reset/confirm", authHandler.ConfirmPasswordReset)
		auth.GET("/security-policy", authHandler.GetSecurityPolicy)
		auth.POST("/generate-password", authHandler.GeneratePassword)
	}

	// MFA management (requires JWT)
	mfa := r.Group("/api/auth/mfa")
	mfa.Use(middleware.JWTAuth(cfg.JWTSecret))
	{
		mfa.POST("/enable", authHandler.EnableMFA)
		mfa.POST("/enable/verify", authHandler.ConfirmEnableMFA)
		mfa.POST("/disable", authHandler.DisableMFA)
	}

	passwordHandler := handlers.NewPasswordHandler(db, enc)
	passwords := r.Group("/api/passwords")
	passwords.Use(middleware.JWTAuth(cfg.JWTSecret))
	{
		passwords.GET("", passwordHandler.List)
		passwords.POST("", passwordHandler.Create)
		passwords.GET("/:id", passwordHandler.Get)
		passwords.PUT("/:id", passwordHandler.Update)
		passwords.DELETE("/:id", passwordHandler.Delete)
	}

	// Sync endpoints
	syncHandler := handlers.NewSyncHandler(db, enc)
	sync := r.Group("/api/sync")
	sync.Use(middleware.JWTAuth(cfg.JWTSecret))
	{
		sync.POST("", syncHandler.Sync)
	}

	// Vault export/import
	exportHandler := handlers.NewExportHandler(db, enc)
	vault := r.Group("/api/vault")
	vault.Use(middleware.JWTAuth(cfg.JWTSecret))
	{
		vault.POST("/export", exportHandler.Export)
		vault.POST("/import", exportHandler.Import)
	}

	// Admin endpoints
	adminHandler := handlers.NewAdminHandler(db, cfg)
	admin := r.Group("/api/admin")
	admin.Use(middleware.JWTAuth(cfg.JWTSecret))
	admin.Use(middleware.AdminRequired(db))
	{
		admin.GET("/settings", adminHandler.GetSettings)
		admin.PUT("/settings", adminHandler.UpdateSettings)
		admin.GET("/users", adminHandler.ListUsers)
	}

	return r
}

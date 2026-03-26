package router

import (
	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/handlers"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Setup(db *gorm.DB, cfg config.Config) *gin.Engine {
	_ = cfg

	r := gin.Default()

	healthHandler := handlers.NewHealthHandler(db)
	r.GET("/health", healthHandler.GetHealth)

	return r
}
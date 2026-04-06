package handlers

import (
	"net/http"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AdminHandler struct {
	db  *gorm.DB
	cfg config.Config
}

func NewAdminHandler(db *gorm.DB, cfg config.Config) *AdminHandler {
	return &AdminHandler{db: db, cfg: cfg}
}

// GetSettings returns all admin-configurable security settings.
func (h *AdminHandler) GetSettings(c *gin.Context) {
	sec := config.GetSecurityFromDB(h.db, h.cfg.Security)
	c.JSON(http.StatusOK, config.SecuritySettingsToMap(sec))
}

// UpdateSettings updates admin-configurable security settings.
func (h *AdminHandler) UpdateSettings(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	validKeys := map[string]bool{
		"min_password_length":  true,
		"require_uppercase":    true,
		"require_lowercase":    true,
		"require_digit":        true,
		"require_special_char": true,
		"max_failed_attempts":  true,
		"lockout_duration":     true,
		"token_expiry":         true,
		"inactivity_timeout":   true,
	}

	for key, value := range req {
		if !validKeys[key] {
			errorJSON(c, http.StatusBadRequest, "invalid setting key: "+key)
			return
		}

		var setting models.AppSetting
		result := h.db.Where("key = ?", key).First(&setting)
		if result.Error != nil {
			setting = models.AppSetting{Key: key, Value: value}
			h.db.Create(&setting)
		} else {
			setting.Value = value
			h.db.Save(&setting)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "settings updated"})
}

// ListUsers returns all users (admin only).
func (h *AdminHandler) ListUsers(c *gin.Context) {
	var users []models.User
	if err := h.db.Find(&users).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to fetch users")
		return
	}

	var result []userResponse
	for _, u := range users {
		result = append(result, toUserResponse(u))
	}

	c.JSON(http.StatusOK, gin.H{"users": result})
}

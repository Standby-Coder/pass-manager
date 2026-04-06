package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type ExportHandler struct {
	db  *gorm.DB
	enc *crypto.FieldEncryptor
}

type vaultExportEntry struct {
	Title     string    `json:"title"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	URL       string    `json:"url"`
	Notes     string    `json:"notes"`
	Category  string    `json:"category"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type vaultExportData struct {
	ExportedAt time.Time          `json:"exported_at"`
	Email      string             `json:"email"`
	Entries    []vaultExportEntry `json:"entries"`
}

type exportRequest struct {
	Password string `json:"password"`
}

type importRequest struct {
	Password string `json:"password"`
	Data     string `json:"data"` // base64-encoded encrypted vault
}

func NewExportHandler(db *gorm.DB, enc *crypto.FieldEncryptor) *ExportHandler {
	return &ExportHandler{db: db, enc: enc}
}

// Export exports the user's vault encrypted with their password.
func (h *ExportHandler) Export(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	var req exportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		errorJSON(c, http.StatusBadRequest, "password is required")
		return
	}

	// Verify user's password
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		errorJSON(c, http.StatusNotFound, "user not found")
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		errorJSON(c, http.StatusUnauthorized, "invalid password")
		return
	}

	// Get all non-deleted entries
	var entries []models.PasswordEntry
	if err := h.db.Where("user_id = ? AND is_deleted = ?", userID, false).Find(&entries).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to fetch entries")
		return
	}

	// Build export data with decrypted passwords
	exportData := vaultExportData{
		ExportedAt: time.Now().UTC(),
		Email:      user.Email,
	}

	for _, e := range entries {
		password, err := h.enc.Decrypt(e.Password)
		if err != nil {
			errorJSON(c, http.StatusInternalServerError, "failed to decrypt entry: "+e.Title)
			return
		}
		exportData.Entries = append(exportData.Entries, vaultExportEntry{
			Title:     e.Title,
			Username:  e.Username,
			Password:  password,
			URL:       e.URL,
			Notes:     e.Notes,
			Category:  e.Category,
			CreatedAt: e.CreatedAt,
			UpdatedAt: e.UpdatedAt,
		})
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(exportData)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to create export")
		return
	}

	// Encrypt with user's password
	encrypted, err := crypto.EncryptData(jsonData, req.Password)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to encrypt export")
		return
	}

	encoded := base64.StdEncoding.EncodeToString(encrypted)

	c.JSON(http.StatusOK, gin.H{
		"data":    encoded,
		"message": "vault exported successfully",
		"count":   len(exportData.Entries),
	})
}

// Import imports vault data encrypted with the user's password.
func (h *ExportHandler) Import(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	var req importRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" || req.Data == "" {
		errorJSON(c, http.StatusBadRequest, "password and data are required")
		return
	}

	// Verify user's password
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		errorJSON(c, http.StatusNotFound, "user not found")
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		errorJSON(c, http.StatusUnauthorized, "invalid password")
		return
	}

	// Decode base64
	encrypted, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid export data format")
		return
	}

	// Decrypt with provided password
	jsonData, err := crypto.DecryptData(encrypted, req.Password)
	if err != nil {
		errorJSON(c, http.StatusBadRequest, "failed to decrypt: wrong password or corrupted data")
		return
	}

	// Parse JSON
	var importData vaultExportData
	if err := json.Unmarshal(jsonData, &importData); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid vault data format")
		return
	}

	// Import entries
	imported := 0
	for _, e := range importData.Entries {
		if e.Title == "" || e.Password == "" {
			continue
		}

		// Encrypt password field for storage
		encrypted, err := h.enc.Encrypt(e.Password)
		if err != nil {
			continue
		}

		entry := models.PasswordEntry{
			UserID:   userID,
			Title:    sanitizeString(e.Title),
			Username: sanitizeString(e.Username),
			Password: encrypted,
			URL:      sanitizeString(e.URL),
			Notes:    sanitizeString(e.Notes),
			Category: sanitizeString(e.Category),
		}

		if err := h.db.Create(&entry).Error; err == nil {
			imported++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "vault imported successfully",
		"imported": imported,
		"total":    len(importData.Entries),
	})
}

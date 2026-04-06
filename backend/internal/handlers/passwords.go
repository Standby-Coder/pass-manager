package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PasswordHandler struct {
	db  *gorm.DB
	enc *crypto.FieldEncryptor
}

type passwordRequest struct {
	Title    string `json:"title"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	Category string `json:"category"`
}

func NewPasswordHandler(db *gorm.DB, enc *crypto.FieldEncryptor) *PasswordHandler {
	return &PasswordHandler{db: db, enc: enc}
}

func (h *PasswordHandler) List(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	query := h.db.Where("user_id = ? AND is_deleted = ?", userID, false)

	// Search filter
	if search := sanitizeString(strings.TrimSpace(c.Query("search"))); search != "" {
		like := "%" + search + "%"
		query = query.Where("title LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ? OR category LIKE ?",
			like, like, like, like, like)
	}

	// Category filter
	if category := sanitizeString(strings.TrimSpace(c.Query("category"))); category != "" {
		query = query.Where("category = ?", category)
	}

	var entries []models.PasswordEntry
	if err := query.Order("id asc").Find(&entries).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to fetch password entries")
		return
	}

	// Decrypt password fields
	for i := range entries {
		decrypted, err := h.enc.Decrypt(entries[i].Password)
		if err == nil {
			entries[i].Password = decrypted
		}
	}

	c.JSON(http.StatusOK, gin.H{"entries": entries})
}

func (h *PasswordHandler) Create(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	var req passwordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	entry := models.PasswordEntry{
		UserID:   userID,
		Title:    sanitizeString(strings.TrimSpace(req.Title)),
		Username: sanitizeString(strings.TrimSpace(req.Username)),
		Password: req.Password,
		URL:      sanitizeString(strings.TrimSpace(req.URL)),
		Notes:    sanitizeString(strings.TrimSpace(req.Notes)),
		Category: sanitizeString(strings.TrimSpace(req.Category)),
	}

	if entry.Title == "" || entry.Password == "" {
		errorJSON(c, http.StatusBadRequest, "title and password are required")
		return
	}

	if len(entry.Title) > 255 {
		errorJSON(c, http.StatusBadRequest, "title must not exceed 255 characters")
		return
	}
	if len(entry.Username) > 255 {
		errorJSON(c, http.StatusBadRequest, "username must not exceed 255 characters")
		return
	}
	if len(entry.URL) > 512 {
		errorJSON(c, http.StatusBadRequest, "URL must not exceed 512 characters")
		return
	}
	if len(entry.Category) > 100 {
		errorJSON(c, http.StatusBadRequest, "category must not exceed 100 characters")
		return
	}
	if len(entry.Notes) > 5000 {
		errorJSON(c, http.StatusBadRequest, "notes must not exceed 5000 characters")
		return
	}

	// Encrypt password field before storing
	encrypted, err := h.enc.Encrypt(entry.Password)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to encrypt password")
		return
	}
	plaintextPassword := entry.Password
	entry.Password = encrypted

	if err := h.db.Create(&entry).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to create password entry")
		return
	}

	// Return plaintext password in response
	entry.Password = plaintextPassword
	c.JSON(http.StatusCreated, entry)
}

func (h *PasswordHandler) Get(c *gin.Context) {
	entry, ok := h.findOwnedEntry(c)
	if !ok {
		return
	}

	// Decrypt password field
	decrypted, err := h.enc.Decrypt(entry.Password)
	if err == nil {
		entry.Password = decrypted
	}

	c.JSON(http.StatusOK, entry)
}

func (h *PasswordHandler) Update(c *gin.Context) {
	entry, ok := h.findOwnedEntry(c)
	if !ok {
		return
	}

	var req passwordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	entry.Title = sanitizeString(strings.TrimSpace(req.Title))
	entry.Username = sanitizeString(strings.TrimSpace(req.Username))
	entry.Password = req.Password
	entry.URL = sanitizeString(strings.TrimSpace(req.URL))
	entry.Notes = sanitizeString(strings.TrimSpace(req.Notes))
	entry.Category = sanitizeString(strings.TrimSpace(req.Category))

	if entry.Title == "" || entry.Password == "" {
		errorJSON(c, http.StatusBadRequest, "title and password are required")
		return
	}

	if len(entry.Title) > 255 {
		errorJSON(c, http.StatusBadRequest, "title must not exceed 255 characters")
		return
	}
	if len(entry.Username) > 255 {
		errorJSON(c, http.StatusBadRequest, "username must not exceed 255 characters")
		return
	}
	if len(entry.URL) > 512 {
		errorJSON(c, http.StatusBadRequest, "URL must not exceed 512 characters")
		return
	}
	if len(entry.Category) > 100 {
		errorJSON(c, http.StatusBadRequest, "category must not exceed 100 characters")
		return
	}
	if len(entry.Notes) > 5000 {
		errorJSON(c, http.StatusBadRequest, "notes must not exceed 5000 characters")
		return
	}

	// Encrypt password field before storing
	encrypted, err := h.enc.Encrypt(entry.Password)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to encrypt password")
		return
	}
	plaintextPassword := entry.Password
	entry.Password = encrypted
	entry.SyncVersion++

	if err := h.db.Save(&entry).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to update password entry")
		return
	}

	entry.Password = plaintextPassword
	c.JSON(http.StatusOK, entry)
}

func (h *PasswordHandler) Delete(c *gin.Context) {
	entry, ok := h.findOwnedEntry(c)
	if !ok {
		return
	}

	// Soft delete for sync support
	entry.IsDeleted = true
	entry.SyncVersion++
	if err := h.db.Save(&entry).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to delete password entry")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password entry deleted"})
}

func (h *PasswordHandler) findOwnedEntry(c *gin.Context) (models.PasswordEntry, bool) {
	userID := middleware.UserIDFromContext(c)
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid password entry id")
		return models.PasswordEntry{}, false
	}

	var entry models.PasswordEntry
	err = h.db.Where("id = ? AND user_id = ? AND is_deleted = ?", uint(id), userID, false).First(&entry).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			errorJSON(c, http.StatusNotFound, "password entry not found")
			return models.PasswordEntry{}, false
		}

		errorJSON(c, http.StatusInternalServerError, "failed to fetch password entry")
		return models.PasswordEntry{}, false
	}

	return entry, true
}

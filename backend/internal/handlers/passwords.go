package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PasswordHandler struct {
	db *gorm.DB
}

type passwordRequest struct {
	Title    string `json:"title"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	Category string `json:"category"`
}

func NewPasswordHandler(db *gorm.DB) *PasswordHandler {
	return &PasswordHandler{db: db}
}

func (h *PasswordHandler) List(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	var entries []models.PasswordEntry
	if err := h.db.Where("user_id = ?", userID).Order("id asc").Find(&entries).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to fetch password entries")
		return
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
		Title:    strings.TrimSpace(req.Title),
		Username: strings.TrimSpace(req.Username),
		Password: req.Password,
		URL:      strings.TrimSpace(req.URL),
		Notes:    strings.TrimSpace(req.Notes),
		Category: strings.TrimSpace(req.Category),
	}

	if entry.Title == "" || entry.Password == "" {
		errorJSON(c, http.StatusBadRequest, "title and password are required")
		return
	}

	if err := h.db.Create(&entry).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to create password entry")
		return
	}

	c.JSON(http.StatusCreated, entry)
}

func (h *PasswordHandler) Get(c *gin.Context) {
	entry, ok := h.findOwnedEntry(c)
	if !ok {
		return
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

	entry.Title = strings.TrimSpace(req.Title)
	entry.Username = strings.TrimSpace(req.Username)
	entry.Password = req.Password
	entry.URL = strings.TrimSpace(req.URL)
	entry.Notes = strings.TrimSpace(req.Notes)
	entry.Category = strings.TrimSpace(req.Category)

	if entry.Title == "" || entry.Password == "" {
		errorJSON(c, http.StatusBadRequest, "title and password are required")
		return
	}

	if err := h.db.Save(&entry).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to update password entry")
		return
	}

	c.JSON(http.StatusOK, entry)
}

func (h *PasswordHandler) Delete(c *gin.Context) {
	entry, ok := h.findOwnedEntry(c)
	if !ok {
		return
	}

	if err := h.db.Delete(&entry).Error; err != nil {
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
	err = h.db.Where("id = ? AND user_id = ?", uint(id), userID).First(&entry).Error
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
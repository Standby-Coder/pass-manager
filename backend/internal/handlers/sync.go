package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type SyncHandler struct {
	db  *gorm.DB
	enc *crypto.FieldEncryptor
}

type syncRequest struct {
	LastSyncAt time.Time          `json:"last_sync_at"`
	Entries    []syncEntryRequest `json:"entries"`
}

type syncEntryRequest struct {
	ClientID    string    `json:"client_id"`
	Title       string    `json:"title"`
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	URL         string    `json:"url"`
	Notes       string    `json:"notes"`
	Category    string    `json:"category"`
	SyncVersion int64     `json:"sync_version"`
	IsDeleted   bool      `json:"is_deleted"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type syncResponse struct {
	Entries   []models.PasswordEntry `json:"entries"`
	SyncAt    time.Time              `json:"sync_at"`
	Conflicts []syncConflict         `json:"conflicts,omitempty"`
}

type syncConflict struct {
	ClientID string               `json:"client_id"`
	Local    syncEntryRequest     `json:"local"`
	Server   models.PasswordEntry `json:"server"`
	Message  string               `json:"message"`
}

func NewSyncHandler(db *gorm.DB, enc *crypto.FieldEncryptor) *SyncHandler {
	return &SyncHandler{db: db, enc: enc}
}

// Sync performs a bidirectional sync between client and server.
// Conflict resolution: server entry wins if its sync_version >= client's sync_version.
func (h *SyncHandler) Sync(c *gin.Context) {
	userID := middleware.UserIDFromContext(c)

	var req syncRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	now := time.Now().UTC()
	var conflicts []syncConflict

	// Process client entries (push)
	for _, clientEntry := range req.Entries {
		if clientEntry.ClientID == "" {
			continue
		}

		var existing models.PasswordEntry
		err := h.db.Where("client_id = ? AND user_id = ?", clientEntry.ClientID, userID).First(&existing).Error

		if err != nil {
			// New entry from client
			if !clientEntry.IsDeleted {
				encrypted, encErr := h.enc.Encrypt(clientEntry.Password)
				if encErr != nil {
					continue
				}

				newEntry := models.PasswordEntry{
					UserID:      userID,
					ClientID:    clientEntry.ClientID,
					Title:       sanitizeString(clientEntry.Title),
					Username:    sanitizeString(clientEntry.Username),
					Password:    encrypted,
					URL:         sanitizeString(clientEntry.URL),
					Notes:       sanitizeString(clientEntry.Notes),
					Category:    sanitizeString(clientEntry.Category),
					SyncVersion: clientEntry.SyncVersion,
					IsDeleted:   false,
				}
				h.db.Create(&newEntry)
			}
			continue
		}

		// Conflict resolution: last-write-wins based on sync_version
		if clientEntry.SyncVersion > existing.SyncVersion {
			// Client wins
			if clientEntry.IsDeleted {
				existing.IsDeleted = true
				existing.SyncVersion = clientEntry.SyncVersion
			} else {
				encrypted, encErr := h.enc.Encrypt(clientEntry.Password)
				if encErr != nil {
					continue
				}
				existing.Title = sanitizeString(clientEntry.Title)
				existing.Username = sanitizeString(clientEntry.Username)
				existing.Password = encrypted
				existing.URL = sanitizeString(clientEntry.URL)
				existing.Notes = sanitizeString(clientEntry.Notes)
				existing.Category = sanitizeString(clientEntry.Category)
				existing.SyncVersion = clientEntry.SyncVersion
				existing.IsDeleted = false
			}
			h.db.Save(&existing)
		} else if clientEntry.SyncVersion == existing.SyncVersion && clientEntry.UpdatedAt.After(existing.UpdatedAt) {
			// Same version but client has newer timestamp - client wins
			if clientEntry.IsDeleted {
				existing.IsDeleted = true
			} else {
				encrypted, encErr := h.enc.Encrypt(clientEntry.Password)
				if encErr != nil {
					continue
				}
				existing.Title = sanitizeString(clientEntry.Title)
				existing.Username = sanitizeString(clientEntry.Username)
				existing.Password = encrypted
				existing.URL = sanitizeString(clientEntry.URL)
				existing.Notes = sanitizeString(clientEntry.Notes)
				existing.Category = sanitizeString(clientEntry.Category)
			}
			existing.SyncVersion++
			h.db.Save(&existing)
		} else if clientEntry.SyncVersion < existing.SyncVersion {
			// Server wins - report conflict
			conflicts = append(conflicts, syncConflict{
				ClientID: clientEntry.ClientID,
				Local:    clientEntry,
				Server:   existing,
				Message:  "server version is newer, server entry kept",
			})
		}
	}

	// Pull: get all entries modified since last sync
	var entries []models.PasswordEntry
	query := h.db.Where("user_id = ?", userID)
	if !req.LastSyncAt.IsZero() {
		query = query.Where("updated_at > ?", req.LastSyncAt)
	}
	query.Find(&entries)

	// Decrypt passwords for response
	for i := range entries {
		decrypted, err := h.enc.Decrypt(entries[i].Password)
		if err == nil {
			entries[i].Password = decrypted
		}
	}

	// Generate client IDs for entries that don't have one
	for i := range entries {
		if entries[i].ClientID == "" {
			clientID, err := generateClientID()
			if err != nil {
				errorJSON(c, http.StatusInternalServerError, "failed to generate client ID")
				return
			}
			entries[i].ClientID = clientID
			h.db.Model(&entries[i]).Update("client_id", clientID)
		}
	}

	c.JSON(http.StatusOK, syncResponse{
		Entries:   entries,
		SyncAt:    now,
		Conflicts: conflicts,
	})
}

func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

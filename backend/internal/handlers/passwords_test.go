package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPasswordTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.PasswordEntry{}); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	return db
}

func authRouter(secret string, db *gorm.DB) *gin.Engine {
	r := gin.New()
	group := r.Group("/api/passwords")
	group.Use(middleware.JWTAuth(secret))

	handler := NewPasswordHandler(db)
	group.GET("", handler.List)
	group.POST("", handler.Create)
	group.GET("/:id", handler.Get)
	group.PUT("/:id", handler.Update)
	group.DELETE("/:id", handler.Delete)

	return r
}

func seedUser(t *testing.T, db *gorm.DB, email string) models.User {
	t.Helper()

	user := models.User{Email: email}
	if err := user.SetPassword("password123"); err != nil {
		t.Fatalf("failed to set password: %v", err)
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func tokenForUser(t *testing.T, db *gorm.DB, secret string, user models.User) string {
	t.Helper()

	handler := NewAuthHandler(db, struct {
		JWTSecret string
	}{JWTSecret: secret})
	_ = handler
	return ""
}

func createToken(t *testing.T, db *gorm.DB, secret string, user models.User) string {
	t.Helper()

	handler := NewAuthHandler(db, configForTests(secret))
	token, err := handler.generateToken(user)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	return token
}

func configForTests(secret string) interface{ JWTSecret string } {
	return struct{ JWTSecret string }{JWTSecret: secret}
}

func TestPasswordHandlerAuthRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPasswordTestDB(t)
	r := authRouter("test-secret", db)

	recorder := performJSONRequest(r, http.MethodGet, "/api/passwords", nil, nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestPasswordHandlerCRUDAndScoping(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPasswordTestDB(t)
	owner := seedUser(t, db, "owner@example.com")
	other := seedUser(t, db, "other@example.com")
	secret := "test-secret"
	r := authRouter(secret, db)

	ownerToken := createTokenFromSecret(t, secret, owner)
	otherToken := createTokenFromSecret(t, secret, other)

	create := performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title":    "GitHub",
		"username": "owner-user",
		"password": "vault-pass",
		"url":      "https://github.com",
		"notes":    "primary account",
		"category": "work",
	}, map[string]string{"Authorization": "Bearer " + ownerToken})

	if create.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", create.Code, create.Body.String())
	}

	var created models.PasswordEntry
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode created entry: %v", err)
	}

	list := performJSONRequest(r, http.MethodGet, "/api/passwords", nil, map[string]string{"Authorization": "Bearer " + ownerToken})
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", list.Code)
	}

	var listResponse struct {
		Entries []models.PasswordEntry `json:"entries"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listResponse); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}

	if len(listResponse.Entries) != 1 || listResponse.Entries[0].ID != created.ID {
		t.Fatalf("expected one owned entry in list, got %+v", listResponse.Entries)
	}

	getOwned := performJSONRequest(r, http.MethodGet, "/api/passwords/"+uintToString(created.ID), nil, map[string]string{"Authorization": "Bearer " + ownerToken})
	if getOwned.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getOwned.Code)
	}

	getOther := performJSONRequest(r, http.MethodGet, "/api/passwords/"+uintToString(created.ID), nil, map[string]string{"Authorization": "Bearer " + otherToken})
	if getOther.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for other user, got %d", getOther.Code)
	}

	update := performJSONRequest(r, http.MethodPut, "/api/passwords/"+uintToString(created.ID), gin.H{
		"title":    "GitHub Updated",
		"username": "new-user",
		"password": "new-pass",
		"url":      "https://example.com",
		"notes":    "updated",
		"category": "personal",
	}, map[string]string{"Authorization": "Bearer " + ownerToken})

	if update.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", update.Code, update.Body.String())
	}

	var updated models.PasswordEntry
	if err := json.Unmarshal(update.Body.Bytes(), &updated); err != nil {
		t.Fatalf("failed to decode updated entry: %v", err)
	}

	if updated.Title != "GitHub Updated" || updated.Password != "new-pass" {
		t.Fatalf("entry not updated correctly: %+v", updated)
	}

	deleteResp := performJSONRequest(r, http.MethodDelete, "/api/passwords/"+uintToString(created.ID), nil, map[string]string{"Authorization": "Bearer " + ownerToken})
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", deleteResp.Code)
	}

	getAfterDelete := performJSONRequest(r, http.MethodGet, "/api/passwords/"+uintToString(created.ID), nil, map[string]string{"Authorization": "Bearer " + ownerToken})
	if getAfterDelete.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", getAfterDelete.Code)
	}
}

func TestPasswordHandlerValidationPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPasswordTestDB(t)
	user := seedUser(t, db, "validator@example.com")
	secret := "test-secret"
	r := authRouter(secret, db)
	token := createTokenFromSecret(t, secret, user)

	createBad := performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title": "",
	}, map[string]string{"Authorization": "Bearer " + token})

	if createBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", createBad.Code)
	}

	getBadID := performJSONRequest(r, http.MethodGet, "/api/passwords/not-a-number", nil, map[string]string{"Authorization": "Bearer " + token})
	if getBadID.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", getBadID.Code)
	}

	missing := performJSONRequest(r, http.MethodGet, "/api/passwords/999", nil, map[string]string{"Authorization": "Bearer " + token})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", missing.Code)
	}
}
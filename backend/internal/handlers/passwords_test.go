package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"pass-manager/backend/internal/middleware"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupPasswordTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}

	if err := db.AutoMigrate(&models.User{}, &models.PasswordEntry{}, &models.AppSetting{}); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	return db
}

func authRouter(secret string, db *gorm.DB) *gin.Engine {
	r := gin.New()
	group := r.Group("/api/passwords")
	group.Use(middleware.JWTAuth(secret))

	handler := NewPasswordHandler(db, nil) // nil encryptor = no encryption in tests
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

func createTokenFromSecret(t *testing.T, secret string, user models.User) string {
	t.Helper()

	now := time.Now()
	claims := models.UserClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func uintToString(id uint) string {
	return fmt.Sprintf("%d", id)
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

func TestPasswordHandlerSearchFilter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPasswordTestDB(t)
	user := seedUser(t, db, "search@example.com")
	secret := "test-secret"
	r := authRouter(secret, db)
	token := createTokenFromSecret(t, secret, user)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	// Create entries
	performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title": "GitHub", "username": "dev", "password": "pass1", "category": "work",
	}, authHeader)
	performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title": "Netflix", "username": "user", "password": "pass2", "category": "personal",
	}, authHeader)
	performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title": "GitLab", "username": "dev", "password": "pass3", "category": "work",
	}, authHeader)

	// Search by title
	searchResp := performJSONRequest(r, http.MethodGet, "/api/passwords?search=git", nil, authHeader)
	if searchResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", searchResp.Code)
	}
	var searchResult struct {
		Entries []models.PasswordEntry `json:"entries"`
	}
	json.Unmarshal(searchResp.Body.Bytes(), &searchResult)
	if len(searchResult.Entries) != 2 {
		t.Fatalf("expected 2 entries matching 'git', got %d", len(searchResult.Entries))
	}

	// Filter by category
	catResp := performJSONRequest(r, http.MethodGet, "/api/passwords?category=personal", nil, authHeader)
	if catResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", catResp.Code)
	}
	var catResult struct {
		Entries []models.PasswordEntry `json:"entries"`
	}
	json.Unmarshal(catResp.Body.Bytes(), &catResult)
	if len(catResult.Entries) != 1 {
		t.Fatalf("expected 1 entry for category 'personal', got %d", len(catResult.Entries))
	}
	if catResult.Entries[0].Title != "Netflix" {
		t.Fatalf("expected Netflix, got %s", catResult.Entries[0].Title)
	}
}

func TestPasswordHandlerInputLengthValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupPasswordTestDB(t)
	user := seedUser(t, db, "length@example.com")
	secret := "test-secret"
	r := authRouter(secret, db)
	token := createTokenFromSecret(t, secret, user)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	// Title too long (>255)
	longTitle := make([]byte, 256)
	for i := range longTitle {
		longTitle[i] = 'a'
	}
	resp := performJSONRequest(r, http.MethodPost, "/api/passwords", gin.H{
		"title": string(longTitle), "password": "test",
	}, authHeader)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for long title, got %d", resp.Code)
	}
}

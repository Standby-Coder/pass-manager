package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthTestDB(t *testing.T) *gorm.DB {
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

func performJSONRequest(r http.Handler, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, req)
	return recorder
}

func TestAuthHandlerRegisterSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	handler := NewAuthHandler(db, config.Config{JWTSecret: "test-secret"})
	handler.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }

	r := gin.New()
	r.POST("/api/auth/register", handler.Register)

	recorder := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":        "USER@example.com ",
		"password":     "super-secret",
		"display_name": "",
	}, nil)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d, body=%s", recorder.Code, recorder.Body.String())
	}

	var response authResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.User.Email != "user@example.com" {
		t.Fatalf("expected normalized email, got %q", response.User.Email)
	}

	if response.User.DisplayName != "user@example.com" {
		t.Fatalf("expected default display name, got %q", response.User.DisplayName)
	}

	if response.Token == "" {
		t.Fatal("expected token to be returned")
	}

	var user models.User
	if err := db.Where("email = ?", "user@example.com").First(&user).Error; err != nil {
		t.Fatalf("expected user in database: %v", err)
	}

	if user.PasswordHash == "super-secret" || user.PasswordHash == "" {
		t.Fatal("expected password to be hashed")
	}
}

func TestAuthHandlerRegisterValidationAndConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	handler := NewAuthHandler(db, config.Config{JWTSecret: "test-secret"})
	r := gin.New()
	r.POST("/api/auth/register", handler.Register)

	badRequest := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email": "",
	}, nil)

	if badRequest.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", badRequest.Code)
	}

	first := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "duplicate@example.com",
		"password": "secret",
	}, nil)

	if first.Code != http.StatusCreated {
		t.Fatalf("expected first create 201, got %d", first.Code)
	}

	conflict := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "duplicate@example.com",
		"password": "secret",
	}, nil)

	if conflict.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d, body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestAuthHandlerLoginSuccessAndFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)

	user := models.User{
		Email:       "login@example.com",
		DisplayName: "Login User",
	}
	if err := user.SetPassword("correct-password"); err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	handler := NewAuthHandler(db, config.Config{JWTSecret: "test-secret"})
	handler.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }

	r := gin.New()
	r.POST("/api/auth/login", handler.Login)

	success := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    " login@example.com ",
		"password": "correct-password",
	}, nil)

	if success.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", success.Code, success.Body.String())
	}

	var response authResponse
	if err := json.Unmarshal(success.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	token, err := jwt.ParseWithClaims(response.Token, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("expected valid token, err=%v", err)
	}

	invalidPassword := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    "login@example.com",
		"password": "wrong",
	}, nil)

	if invalidPassword.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", invalidPassword.Code)
	}

	notFound := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    "missing@example.com",
		"password": "whatever",
	}, nil)

	if notFound.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", notFound.Code)
	}
}
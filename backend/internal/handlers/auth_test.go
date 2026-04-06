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

func testConfig() config.Config {
	return config.Config{
		JWTSecret:      "test-secret",
		AllowedOrigins: "http://localhost:5173",
		Security: config.SecurityConfig{
			MinPasswordLength:  8,
			RequireUppercase:   true,
			RequireLowercase:   true,
			RequireDigit:       true,
			RequireSpecialChar: true,
			MaxFailedAttempts:  3,
			LockoutDuration:    5 * time.Minute,
			TokenExpiry:        1 * time.Hour,
			InactivityTimeout:  15 * time.Minute,
		},
	}
}

func setupAuthTestDB(t *testing.T) *gorm.DB {
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
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)
	handler.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }

	r := gin.New()
	r.POST("/api/auth/register", handler.Register)

	recorder := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":        "USER@example.com ",
		"password":     "Super-secret1!",
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

	if user.PasswordHash == "Super-secret1!" || user.PasswordHash == "" {
		t.Fatal("expected password to be hashed")
	}
}

func TestAuthHandlerRegisterValidationAndConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)
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
		"password": "StrongPass1!",
	}, nil)

	if first.Code != http.StatusCreated {
		t.Fatalf("expected first create 201, got %d, body=%s", first.Code, first.Body.String())
	}

	conflict := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "duplicate@example.com",
		"password": "StrongPass1!",
	}, nil)

	if conflict.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d, body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestAuthHandlerLoginSuccessAndFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()

	user := models.User{
		Email:       "login@example.com",
		DisplayName: "Login User",
	}
	if err := user.SetPassword("Correct-pass1!"); err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/login", handler.Login)

	success := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    " login@example.com ",
		"password": "Correct-pass1!",
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

func TestPasswordValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/register", handler.Register)

	// Too short
	short := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "short@example.com",
		"password": "Ab1!",
	}, nil)
	if short.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", short.Code)
	}

	// No uppercase
	noUpper := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "noupper@example.com",
		"password": "lowercase1!a",
	}, nil)
	if noUpper.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no uppercase, got %d, body=%s", noUpper.Code, noUpper.Body.String())
	}

	// No digit
	noDigit := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "nodigit@example.com",
		"password": "NoDigitHere!",
	}, nil)
	if noDigit.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no digit, got %d, body=%s", noDigit.Code, noDigit.Body.String())
	}

	// No special char
	noSpecial := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "nospecial@example.com",
		"password": "NoSpecial1a",
	}, nil)
	if noSpecial.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for no special char, got %d, body=%s", noSpecial.Code, noSpecial.Body.String())
	}

	// Valid password
	valid := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "valid@example.com",
		"password": "ValidPass1!",
	}, nil)
	if valid.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body=%s", valid.Code, valid.Body.String())
	}
}

func TestAccountLockout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	cfg.Security.MaxFailedAttempts = 3

	user := models.User{
		Email:       "lockout@example.com",
		DisplayName: "Lockout User",
	}
	if err := user.SetPassword("Correct-pass1!"); err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/login", handler.Login)

	// Fail 3 times
	for i := 0; i < 3; i++ {
		resp := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
			"email":    "lockout@example.com",
			"password": "wrong-password",
		}, nil)

		if i < 2 {
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("attempt %d: expected 401, got %d", i+1, resp.Code)
			}
		} else {
			// 3rd attempt should trigger lockout
			if resp.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: expected 429, got %d, body=%s", i+1, resp.Code, resp.Body.String())
			}
		}
	}

	// Even correct password should fail while locked
	locked := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    "lockout@example.com",
		"password": "Correct-pass1!",
	}, nil)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while locked, got %d", locked.Code)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()

	user := models.User{
		Email:       "reset@example.com",
		DisplayName: "Reset User",
	}
	if err := user.SetPassword("OldPass1!abc"); err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/password-reset/request", handler.RequestPasswordReset)
	r.POST("/api/auth/password-reset/confirm", handler.ConfirmPasswordReset)
	r.POST("/api/auth/login", handler.Login)

	// Request reset
	requestResp := performJSONRequest(r, http.MethodPost, "/api/auth/password-reset/request", gin.H{
		"email": "reset@example.com",
	}, nil)
	if requestResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", requestResp.Code)
	}

	var resetResp map[string]string
	if err := json.Unmarshal(requestResp.Body.Bytes(), &resetResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	resetToken := resetResp["reset_token"]
	if resetToken == "" {
		t.Fatal("expected reset_token in response")
	}

	// Confirm reset with new password
	confirmResp := performJSONRequest(r, http.MethodPost, "/api/auth/password-reset/confirm", gin.H{
		"token":        resetToken,
		"new_password": "NewPass1!xyz",
	}, nil)
	if confirmResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", confirmResp.Code, confirmResp.Body.String())
	}

	// Login with new password
	loginResp := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    "reset@example.com",
		"password": "NewPass1!xyz",
	}, nil)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", loginResp.Code, loginResp.Body.String())
	}

	// Old password should fail
	oldPassResp := performJSONRequest(r, http.MethodPost, "/api/auth/login", gin.H{
		"email":    "reset@example.com",
		"password": "OldPass1!abc",
	}, nil)
	if oldPassResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", oldPassResp.Code)
	}

	// Invalid token should fail
	badTokenResp := performJSONRequest(r, http.MethodPost, "/api/auth/password-reset/confirm", gin.H{
		"token":        "invalid-token",
		"new_password": "NewPass2!abc",
	}, nil)
	if badTokenResp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", badTokenResp.Code)
	}
}

func TestGeneratePassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/generate-password", handler.GeneratePassword)

	// Default length
	resp := performJSONRequest(r, http.MethodPost, "/api/auth/generate-password", gin.H{}, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", resp.Code, resp.Body.String())
	}

	var genResp generatePasswordResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &genResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(genResp.Password) < cfg.Security.MinPasswordLength {
		t.Fatalf("generated password too short: %d", len(genResp.Password))
	}

	// Generated password should pass validation
	errs := validatePassword(genResp.Password, cfg.Security)
	if len(errs) > 0 {
		t.Fatalf("generated password fails validation: %v, password=%q", errs, genResp.Password)
	}

	// Custom length
	customResp := performJSONRequest(r, http.MethodPost, "/api/auth/generate-password", gin.H{
		"length": 24,
	}, nil)
	if customResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", customResp.Code)
	}

	var customGenResp generatePasswordResponse
	if err := json.Unmarshal(customResp.Body.Bytes(), &customGenResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(customGenResp.Password) != 24 {
		t.Fatalf("expected password of length 24, got %d", len(customGenResp.Password))
	}
}

func TestSecurityPolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.GET("/api/auth/security-policy", handler.GetSecurityPolicy)

	resp := performJSONRequest(r, http.MethodGet, "/api/auth/security-policy", nil, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}

	var policy map[string]interface{}
	if err := json.Unmarshal(resp.Body.Bytes(), &policy); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if policy["min_password_length"].(float64) != float64(cfg.Security.MinPasswordLength) {
		t.Fatalf("expected min_password_length=%d, got %v", cfg.Security.MinPasswordLength, policy["min_password_length"])
	}

	if policy["require_uppercase"].(bool) != cfg.Security.RequireUppercase {
		t.Fatalf("expected require_uppercase=%v", cfg.Security.RequireUppercase)
	}
}

func TestEmailValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/register", handler.Register)

	badEmail := performJSONRequest(r, http.MethodPost, "/api/auth/register", gin.H{
		"email":    "not-an-email",
		"password": "StrongPass1!",
	}, nil)
	if badEmail.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d", badEmail.Code)
	}
}

func TestPasswordResetNonExistentEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupAuthTestDB(t)
	cfg := testConfig()
	handler := NewAuthHandler(db, cfg)

	r := gin.New()
	r.POST("/api/auth/password-reset/request", handler.RequestPasswordReset)

	// Should return 200 even for non-existent email (prevent email enumeration)
	resp := performJSONRequest(r, http.MethodPost, "/api/auth/password-reset/request", gin.H{
		"email": "nonexistent@example.com",
	}, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
}

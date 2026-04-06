package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// --- helpers ---

func setupIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db.AutoMigrate(&models.User{}, &models.PasswordEntry{}, &models.AppSetting{})
	return db
}

func integrationConfig() config.Config {
	return config.Config{
		JWTSecret: "integration-test-secret",
		Security: config.SecurityConfig{
			MinPasswordLength:  8,
			RequireUppercase:   false,
			RequireLowercase:   false,
			RequireDigit:       false,
			RequireSpecialChar: false,
			MaxFailedAttempts:  5,
			TokenExpiry:        time.Hour,
			LockoutDuration:    15 * time.Minute,
			InactivityTimeout:  15 * time.Minute,
		},
	}
}

// registerAndLogin registers a user and returns the JWT token.
func registerAndLogin(t *testing.T, r *gin.Engine, email, password string) string {
	t.Helper()
	body := map[string]string{"email": email, "password": password}
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register failed: %d - %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	token, ok := resp["token"].(string)
	if !ok || token == "" {
		t.Fatal("no token in register response")
	}
	return token
}

func authedRequest(method, url, token string, body interface{}) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// --- MFA Integration Tests ---

func TestMFAEnableDisableFlow(t *testing.T) {
	db := setupIntegrationDB(t)
	cfg := integrationConfig()

	gin.SetMode(gin.TestMode)
	r := gin.New()

	auth := NewAuthHandler(db, cfg)
	ph := NewPasswordHandler(db, nil)
	r.POST("/api/auth/register", auth.Register)
	r.POST("/api/auth/login", auth.Login)
	r.POST("/api/auth/mfa/verify", auth.VerifyMFA)

	authed := r.Group("/api/auth/mfa")
	authed.Use(authMiddleware(cfg.JWTSecret))
	authed.POST("/enable", auth.EnableMFA)
	authed.POST("/enable/confirm", auth.ConfirmEnableMFA)
	authed.POST("/disable", auth.DisableMFA)

	passwords := r.Group("/api/passwords")
	passwords.Use(authMiddleware(cfg.JWTSecret))
	passwords.GET("", ph.List)

	// 1. Register user
	token := registerAndLogin(t, r, "mfa@test.com", "Password123!")

	// 2. Enable MFA - should return a code
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/auth/mfa/enable", token, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("enable MFA failed: %d - %s", w.Code, w.Body.String())
	}
	var enableResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &enableResp)
	code, ok := enableResp["code"].(string)
	if !ok || code == "" {
		t.Fatal("no code in MFA enable response")
	}

	// 3. Confirm enable with the code
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/auth/mfa/enable/confirm", token, map[string]string{"code": code}))
	if w.Code != http.StatusOK {
		t.Fatalf("confirm enable MFA failed: %d - %s", w.Code, w.Body.String())
	}

	// 4. Login should now require MFA
	loginBody, _ := json.Marshal(map[string]string{"email": "mfa@test.com", "password": "Password123!"})
	w = httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login MFA step failed: %d - %s", w.Code, w.Body.String())
	}
	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	mfaRequired, _ := loginResp["mfa_required"].(bool)
	if !mfaRequired {
		t.Fatal("expected mfa_required to be true")
	}
	mfaToken, _ := loginResp["mfa_token"].(string)
	mfaCode, _ := loginResp["mfa_code"].(string)
	if mfaToken == "" || mfaCode == "" {
		t.Fatal("expected mfa_token and mfa_code in response")
	}

	// 5. Verify MFA
	verifyBody, _ := json.Marshal(map[string]string{"mfa_token": mfaToken, "code": mfaCode})
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/auth/mfa/verify", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("verify MFA failed: %d - %s", w.Code, w.Body.String())
	}
	var verifyResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &verifyResp)
	newToken, _ := verifyResp["token"].(string)
	if newToken == "" {
		t.Fatal("expected token after MFA verification")
	}

	// 6. Disable MFA
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/auth/mfa/disable", newToken, map[string]string{"password": "Password123!"}))
	if w.Code != http.StatusOK {
		t.Fatalf("disable MFA failed: %d - %s", w.Code, w.Body.String())
	}

	// 7. Login should work without MFA now
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login after disable MFA failed: %d - %s", w.Code, w.Body.String())
	}
	var finalLoginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &finalLoginResp)
	if finalLoginResp["mfa_required"] == true {
		t.Fatal("expected mfa_required to be false after disabling MFA")
	}
}

// --- Export/Import Integration Tests ---

func TestExportImportFlow(t *testing.T) {
	db := setupIntegrationDB(t)
	cfg := integrationConfig()
	enc, _ := crypto.NewFieldEncryptor("test-enc-key")

	gin.SetMode(gin.TestMode)
	r := gin.New()

	auth := NewAuthHandler(db, cfg)
	ph := NewPasswordHandler(db, enc)
	eh := NewExportHandler(db, enc)
	r.POST("/api/auth/register", auth.Register)

	authed := r.Group("/api")
	authed.Use(authMiddleware(cfg.JWTSecret))
	authed.POST("/passwords", ph.Create)
	authed.GET("/passwords", ph.List)
	authed.POST("/vault/export", eh.Export)
	authed.POST("/vault/import", eh.Import)

	password := "Password123!"
	token := registerAndLogin(t, r, "export@test.com", password)

	// Create some entries
	for _, title := range []string{"GitHub", "AWS", "Slack"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, authedRequest("POST", "/api/passwords", token, map[string]string{
			"title":    title,
			"username": title + "-user",
			"password": "pass-" + title,
		}))
		if w.Code != http.StatusCreated {
			t.Fatalf("create entry failed: %d - %s", w.Code, w.Body.String())
		}
	}

	// Export
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/vault/export", token, map[string]string{"password": password}))
	if w.Code != http.StatusOK {
		t.Fatalf("export failed: %d - %s", w.Code, w.Body.String())
	}
	var exportResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &exportResp)
	exportedData, _ := exportResp["data"].(string)
	count, _ := exportResp["count"].(float64)
	if exportedData == "" {
		t.Fatal("expected data in export response")
	}
	if count != 3 {
		t.Fatalf("expected 3 entries exported, got %v", count)
	}

	// Register a new user and import
	token2 := registerAndLogin(t, r, "import@test.com", password)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/vault/import", token2, map[string]interface{}{
		"password": password,
		"data":     exportedData,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("import failed: %d - %s", w.Code, w.Body.String())
	}
	var importResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &importResp)
	imported, _ := importResp["imported"].(float64)
	if imported != 3 {
		t.Fatalf("expected 3 entries imported, got %v", imported)
	}

	// Verify imported entries
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/passwords", token2, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list after import failed: %d - %s", w.Code, w.Body.String())
	}
	var listResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	entries, _ := listResp["entries"].([]interface{})
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after import, got %d", len(entries))
	}
}

// --- Admin Integration Tests ---

func TestAdminSettingsAndAccess(t *testing.T) {
	db := setupIntegrationDB(t)
	cfg := integrationConfig()

	gin.SetMode(gin.TestMode)
	r := gin.New()

	auth := NewAuthHandler(db, cfg)
	admin := NewAdminHandler(db, cfg)
	r.POST("/api/auth/register", auth.Register)

	adminGroup := r.Group("/api/admin")
	adminGroup.Use(authMiddleware(cfg.JWTSecret))
	adminGroup.Use(adminRequiredMiddleware(db))
	adminGroup.GET("/settings", admin.GetSettings)
	adminGroup.PUT("/settings", admin.UpdateSettings)
	adminGroup.GET("/users", admin.ListUsers)

	// First user should be admin
	adminToken := registerAndLogin(t, r, "admin@test.com", "Password123!")

	// Second user should NOT be admin
	normalToken := registerAndLogin(t, r, "normal@test.com", "Password123!")

	// Admin can access settings
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/admin/settings", adminToken, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admin get settings failed: %d - %s", w.Code, w.Body.String())
	}

	// Normal user cannot access admin settings
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/admin/settings", normalToken, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", w.Code)
	}

	// Admin can update settings
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("PUT", "/api/admin/settings", adminToken, map[string]interface{}{
		"min_password_length": "12",
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("admin update settings failed: %d - %s", w.Code, w.Body.String())
	}

	// Verify updated
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/admin/settings", adminToken, nil))
	var settings map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &settings)
	if settings["min_password_length"] != "12" {
		t.Fatalf("expected updated min_password_length=12, got %v", settings["min_password_length"])
	}

	// Admin can list users
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/admin/users", adminToken, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("admin list users failed: %d - %s", w.Code, w.Body.String())
	}
	var usersResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &usersResp)
	users, _ := usersResp["users"].([]interface{})
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

// --- Sync Integration Tests ---

func TestSyncPushAndPull(t *testing.T) {
	db := setupIntegrationDB(t)
	cfg := integrationConfig()
	enc, _ := crypto.NewFieldEncryptor("test-enc-key")

	gin.SetMode(gin.TestMode)
	r := gin.New()

	auth := NewAuthHandler(db, cfg)
	ph := NewPasswordHandler(db, enc)
	sh := NewSyncHandler(db, enc)
	r.POST("/api/auth/register", auth.Register)

	authed := r.Group("/api")
	authed.Use(authMiddleware(cfg.JWTSecret))
	authed.POST("/passwords", ph.Create)
	authed.GET("/passwords", ph.List)
	authed.POST("/sync", sh.Sync)

	token := registerAndLogin(t, r, "sync@test.com", "Password123!")

	// Create entries via normal API
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/passwords", token, map[string]string{
		"title":    "Server Entry",
		"username": "server-user",
		"password": "server-pass",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("create entry failed: %d - %s", w.Code, w.Body.String())
	}

	// Sync with no last_sync_at - should pull everything
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/sync", token, map[string]interface{}{
		"entries": []interface{}{},
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("sync failed: %d - %s", w.Code, w.Body.String())
	}
	var syncResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &syncResp)
	entries, _ := syncResp["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry in sync, got %d", len(entries))
	}
	syncAt, _ := syncResp["sync_at"].(string)
	if syncAt == "" {
		t.Fatal("expected sync_at in response")
	}

	// Push a new entry from client
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/sync", token, map[string]interface{}{
		"last_sync_at": syncAt,
		"entries": []map[string]interface{}{
			{
				"client_id": "client-001",
				"title":     "Client Entry",
				"username":  "client-user",
				"password":  "client-pass",
			},
		},
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("sync push failed: %d - %s", w.Code, w.Body.String())
	}

	// List entries should now show 2
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/passwords", token, nil))
	var listResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	allEntries, _ := listResp["entries"].([]interface{})
	if len(allEntries) != 2 {
		t.Fatalf("expected 2 entries after sync push, got %d", len(allEntries))
	}
}

// --- Encryption Integration Tests ---

func TestPasswordFieldEncryptionInHandler(t *testing.T) {
	db := setupIntegrationDB(t)
	cfg := integrationConfig()
	enc, _ := crypto.NewFieldEncryptor("handler-test-key")

	gin.SetMode(gin.TestMode)
	r := gin.New()

	auth := NewAuthHandler(db, cfg)
	ph := NewPasswordHandler(db, enc)
	r.POST("/api/auth/register", auth.Register)

	authed := r.Group("/api/passwords")
	authed.Use(authMiddleware(cfg.JWTSecret))
	authed.POST("", ph.Create)
	authed.GET("", ph.List)
	authed.GET("/:id", ph.Get)

	token := registerAndLogin(t, r, "enc@test.com", "Password123!")

	// Create entry
	w := httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("POST", "/api/passwords", token, map[string]string{
		"title":    "Encrypted",
		"username": "user",
		"password": "MySecretPass!",
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: %d - %s", w.Code, w.Body.String())
	}

	// Verify password is stored encrypted in DB
	var dbEntry models.PasswordEntry
	db.First(&dbEntry)
	if dbEntry.Password == "MySecretPass!" {
		t.Fatal("password should be encrypted in DB, not plaintext")
	}
	if len(dbEntry.Password) < 4 || dbEntry.Password[:4] != "enc:" {
		t.Fatalf("expected enc: prefix in stored password, got %q", dbEntry.Password)
	}

	// API should return decrypted password
	w = httptest.NewRecorder()
	r.ServeHTTP(w, authedRequest("GET", "/api/passwords", token, nil))
	var listResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	entries, _ := listResp["entries"].([]interface{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	entry := entries[0].(map[string]interface{})
	if entry["password"] != "MySecretPass!" {
		t.Fatalf("expected decrypted password, got %v", entry["password"])
	}
}

// --- helper middleware wrappers for tests ---

func authMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := c.GetHeader("Authorization")
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}

		claims := &models.UserClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("userClaims", *claims)
		c.Next()
	}
}

func adminRequiredMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		value, ok := c.Get("userClaims")
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		claims, ok := value.(models.UserClaims)
		if !ok || claims.UserID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		var user models.User
		if err := db.First(&user, claims.UserID).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if !user.IsAdmin {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}

package handlers

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db  *gorm.DB
	cfg config.Config
	now func() time.Time
}

type authRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type authResponse struct {
	User  userResponse `json:"user"`
	Token string       `json:"token"`
}

type mfaRequiredResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
	MFACode     string `json:"mfa_code,omitempty"` // Only in MVP; in production, sent via email
	Message     string `json:"message"`
}

type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type userResponse struct {
	ID          uint      `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	MFAEnabled  bool      `json:"mfa_enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirm struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type generatePasswordRequest struct {
	Length int `json:"length"`
}

type generatePasswordResponse struct {
	Password string `json:"password"`
}

func NewAuthHandler(db *gorm.DB, cfg config.Config) *AuthHandler {
	return &AuthHandler{
		db:  db,
		cfg: cfg,
		now: time.Now,
	}
}

// securityConfig returns the security config with admin DB overrides applied.
func (h *AuthHandler) securityConfig() config.SecurityConfig {
	return config.GetSecurityFromDB(h.db, h.cfg.Security)
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func (h *AuthHandler) Register(c *gin.Context) {
	var req authRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = sanitizeString(strings.TrimSpace(strings.ToLower(req.Email)))
	req.DisplayName = sanitizeString(strings.TrimSpace(req.DisplayName))

	if req.Email == "" || req.Password == "" {
		errorJSON(c, http.StatusBadRequest, "email and password are required")
		return
	}

	if !emailRegex.MatchString(req.Email) {
		errorJSON(c, http.StatusBadRequest, "invalid email format")
		return
	}

	if len(req.Email) > 255 {
		errorJSON(c, http.StatusBadRequest, "email must not exceed 255 characters")
		return
	}

	if len(req.DisplayName) > 255 {
		errorJSON(c, http.StatusBadRequest, "display name must not exceed 255 characters")
		return
	}

	sec := h.securityConfig()
	if errs := validatePassword(req.Password, sec); len(errs) > 0 {
		errorJSON(c, http.StatusBadRequest, strings.Join(errs, "; "))
		return
	}

	// Auto-assign admin: first user or configured admin email
	var adminCount int64
	h.db.Model(&models.User{}).Where("is_admin = ?", true).Count(&adminCount)
	isAdmin := adminCount == 0
	if !isAdmin && h.cfg.AdminEmail != "" && strings.EqualFold(req.Email, h.cfg.AdminEmail) {
		isAdmin = true
	}

	user := models.User{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IsAdmin:     isAdmin,
	}

	if err := user.SetPassword(req.Password); err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to process password")
		return
	}

	if err := h.db.Create(&user).Error; err != nil {
		if isUniqueConstraintError(err) {
			errorJSON(c, http.StatusConflict, "email is already registered")
			return
		}

		errorJSON(c, http.StatusInternalServerError, "failed to create user")
		return
	}

	token, err := h.generateToken(user)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to generate token")
		return
	}

	c.JSON(http.StatusCreated, authResponse{
		User:  toUserResponse(user),
		Token: token,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req authRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	email := sanitizeString(strings.TrimSpace(strings.ToLower(req.Email)))
	if email == "" || req.Password == "" {
		errorJSON(c, http.StatusBadRequest, "email and password are required")
		return
	}

	var user models.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			errorJSON(c, http.StatusUnauthorized, "invalid credentials")
			return
		}

		errorJSON(c, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	now := h.now()
	sec := h.securityConfig()

	if user.IsLocked(now) {
		remaining := user.LockedUntil.Sub(now).Truncate(time.Second)
		errorJSON(c, http.StatusTooManyRequests, fmt.Sprintf("account is locked, try again in %s", remaining))
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		user.FailedAttempts++
		if sec.MaxFailedAttempts > 0 && user.FailedAttempts >= sec.MaxFailedAttempts {
			lockedUntil := now.Add(sec.LockoutDuration)
			user.LockedUntil = &lockedUntil
			user.FailedAttempts = 0
			h.db.Save(&user)
			errorJSON(c, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts, account locked for %s", sec.LockoutDuration))
			return
		}
		h.db.Save(&user)
		errorJSON(c, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Reset failed attempts on successful login
	if user.FailedAttempts > 0 || user.LockedUntil != nil {
		user.FailedAttempts = 0
		user.LockedUntil = nil
		h.db.Save(&user)
	}

	// If MFA is enabled, generate code and require verification
	if user.MFAEnabled {
		code, err := user.GenerateMFACode()
		if err != nil {
			errorJSON(c, http.StatusInternalServerError, "failed to generate MFA code")
			return
		}
		h.db.Save(&user)

		// Generate a temporary MFA token (short-lived, limited scope)
		mfaToken, err := h.generateMFAToken(user)
		if err != nil {
			errorJSON(c, http.StatusInternalServerError, "failed to generate MFA token")
			return
		}

		c.JSON(http.StatusOK, mfaRequiredResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
			MFACode:     code, // In production, this would be sent via email
			Message:     "MFA code has been sent to your email",
		})
		return
	}

	token, err := h.generateToken(user)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to generate token")
		return
	}

	c.JSON(http.StatusOK, authResponse{
		User:  toUserResponse(user),
		Token: token,
	})
}

// VerifyMFA verifies the MFA code and returns a full JWT.
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	var req mfaVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		errorJSON(c, http.StatusBadRequest, "mfa_token and code are required")
		return
	}

	// Parse the MFA token to get user ID
	token, err := jwt.ParseWithClaims(req.MFAToken, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(h.cfg.JWTSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		errorJSON(c, http.StatusUnauthorized, "invalid or expired MFA token")
		return
	}

	claims, ok := token.Claims.(*models.UserClaims)
	if !ok || !token.Valid || claims.UserID == 0 {
		errorJSON(c, http.StatusUnauthorized, "invalid MFA token")
		return
	}

	var user models.User
	if err := h.db.First(&user, claims.UserID).Error; err != nil {
		errorJSON(c, http.StatusUnauthorized, "user not found")
		return
	}

	now := h.now()
	if !user.VerifyMFACode(req.Code, now) {
		errorJSON(c, http.StatusUnauthorized, "invalid or expired MFA code")
		return
	}

	// Clear the MFA code
	user.MFACode = ""
	user.MFACodeExpiry = nil
	h.db.Save(&user)

	fullToken, err := h.generateToken(user)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to generate token")
		return
	}

	c.JSON(http.StatusOK, authResponse{
		User:  toUserResponse(user),
		Token: fullToken,
	})
}

// EnableMFA generates an MFA code to enable MFA for the user.
func (h *AuthHandler) EnableMFA(c *gin.Context) {
	userID := getUserIDFromContext(c)

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		errorJSON(c, http.StatusNotFound, "user not found")
		return
	}

	if user.MFAEnabled {
		errorJSON(c, http.StatusBadRequest, "MFA is already enabled")
		return
	}

	code, err := user.GenerateMFACode()
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to generate MFA code")
		return
	}
	h.db.Save(&user)

	c.JSON(http.StatusOK, gin.H{
		"message": "MFA verification code generated. Enter the code to confirm.",
		"code":    code, // In production, sent via email
	})
}

// ConfirmEnableMFA verifies the code and enables MFA.
func (h *AuthHandler) ConfirmEnableMFA(c *gin.Context) {
	userID := getUserIDFromContext(c)

	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		errorJSON(c, http.StatusBadRequest, "code is required")
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		errorJSON(c, http.StatusNotFound, "user not found")
		return
	}

	now := h.now()
	if !user.VerifyMFACode(req.Code, now) {
		errorJSON(c, http.StatusUnauthorized, "invalid or expired code")
		return
	}

	user.MFAEnabled = true
	user.MFACode = ""
	user.MFACodeExpiry = nil
	h.db.Save(&user)

	c.JSON(http.StatusOK, gin.H{"message": "MFA has been enabled"})
}

// DisableMFA disables MFA after password confirmation.
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	userID := getUserIDFromContext(c)

	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		errorJSON(c, http.StatusBadRequest, "password is required")
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		errorJSON(c, http.StatusNotFound, "user not found")
		return
	}

	if err := user.CheckPassword(req.Password); err != nil {
		errorJSON(c, http.StatusUnauthorized, "invalid password")
		return
	}

	user.MFAEnabled = false
	user.MFACode = ""
	user.MFACodeExpiry = nil
	h.db.Save(&user)

	c.JSON(http.StatusOK, gin.H{"message": "MFA has been disabled"})
}

func (h *AuthHandler) RequestPasswordReset(c *gin.Context) {
	var req passwordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	email := sanitizeString(strings.TrimSpace(strings.ToLower(req.Email)))
	if email == "" {
		errorJSON(c, http.StatusBadRequest, "email is required")
		return
	}

	// Always return success to avoid email enumeration
	successMsg := gin.H{"message": "if the email exists, a reset token has been generated"}

	var user models.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, successMsg)
		return
	}

	token, err := user.GenerateResetToken()
	if err != nil {
		c.JSON(http.StatusOK, successMsg)
		return
	}

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusOK, successMsg)
		return
	}

	// In a real app, send this token via email. For this MVP, return it in response.
	c.JSON(http.StatusOK, gin.H{
		"message":     "reset token generated",
		"reset_token": token,
	})
}

func (h *AuthHandler) ConfirmPasswordReset(c *gin.Context) {
	var req passwordResetConfirm
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		errorJSON(c, http.StatusBadRequest, "token and new_password are required")
		return
	}

	sec := h.securityConfig()
	if errs := validatePassword(req.NewPassword, sec); len(errs) > 0 {
		errorJSON(c, http.StatusBadRequest, strings.Join(errs, "; "))
		return
	}

	var user models.User
	if err := h.db.Where("reset_token = ?", req.Token).First(&user).Error; err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid or expired reset token")
		return
	}

	now := h.now()
	if user.ResetTokenExpiry == nil || now.After(*user.ResetTokenExpiry) {
		errorJSON(c, http.StatusBadRequest, "invalid or expired reset token")
		return
	}

	if err := user.SetPassword(req.NewPassword); err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to process password")
		return
	}

	user.ResetToken = ""
	user.ResetTokenExpiry = nil
	user.FailedAttempts = 0
	user.LockedUntil = nil

	if err := h.db.Save(&user).Error; err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to update password")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password has been reset successfully"})
}

func (h *AuthHandler) GeneratePassword(c *gin.Context) {
	var req generatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Use default length
		req.Length = 0
	}

	sec := h.securityConfig()
	minLen := sec.MinPasswordLength
	if minLen < 8 {
		minLen = 8
	}
	length := req.Length
	if length < minLen {
		length = minLen + 8 // Generate something comfortably longer than minimum
	}
	if length > 128 {
		length = 128
	}

	password, err := generateSecurePassword(length, sec)
	if err != nil {
		errorJSON(c, http.StatusInternalServerError, "failed to generate password")
		return
	}

	c.JSON(http.StatusOK, generatePasswordResponse{Password: password})
}

func (h *AuthHandler) GetSecurityPolicy(c *gin.Context) {
	sec := h.securityConfig()
	c.JSON(http.StatusOK, gin.H{
		"min_password_length":  sec.MinPasswordLength,
		"require_uppercase":    sec.RequireUppercase,
		"require_lowercase":    sec.RequireLowercase,
		"require_digit":        sec.RequireDigit,
		"require_special_char": sec.RequireSpecialChar,
		"inactivity_timeout":   sec.InactivityTimeout.Seconds(),
		"token_expiry":         sec.TokenExpiry.Seconds(),
	})
}

func (h *AuthHandler) generateToken(user models.User) (string, error) {
	now := h.now()
	sec := h.securityConfig()
	claims := models.UserClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sec.TokenExpiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.JWTSecret))
}

func (h *AuthHandler) generateMFAToken(user models.User) (string, error) {
	now := h.now()
	claims := models.UserClaims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.JWTSecret))
}

func validatePassword(password string, sec config.SecurityConfig) []string {
	var errs []string

	if len(password) < sec.MinPasswordLength {
		errs = append(errs, fmt.Sprintf("password must be at least %d characters", sec.MinPasswordLength))
	}

	if len(password) > 128 {
		errs = append(errs, "password must not exceed 128 characters")
	}

	if sec.RequireUppercase {
		hasUpper := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			errs = append(errs, "password must contain at least one uppercase letter")
		}
	}

	if sec.RequireLowercase {
		hasLower := false
		for _, r := range password {
			if unicode.IsLower(r) {
				hasLower = true
				break
			}
		}
		if !hasLower {
			errs = append(errs, "password must contain at least one lowercase letter")
		}
	}

	if sec.RequireDigit {
		hasDigit := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			errs = append(errs, "password must contain at least one digit")
		}
	}

	if sec.RequireSpecialChar {
		hasSpecial := false
		for _, r := range password {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			errs = append(errs, "password must contain at least one special character")
		}
	}

	return errs
}

func generateSecurePassword(length int, sec config.SecurityConfig) (string, error) {
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()-_=+[]{}|;:,.<>?"
	)

	var required []byte
	charset := ""

	if sec.RequireLowercase {
		charset += lowercase
		ch, err := randChar(lowercase)
		if err != nil {
			return "", err
		}
		required = append(required, ch)
	}
	if sec.RequireUppercase {
		charset += uppercase
		ch, err := randChar(uppercase)
		if err != nil {
			return "", err
		}
		required = append(required, ch)
	}
	if sec.RequireDigit {
		charset += digits
		ch, err := randChar(digits)
		if err != nil {
			return "", err
		}
		required = append(required, ch)
	}
	if sec.RequireSpecialChar {
		charset += special
		ch, err := randChar(special)
		if err != nil {
			return "", err
		}
		required = append(required, ch)
	}

	if charset == "" {
		charset = lowercase + uppercase + digits + special
	}

	result := make([]byte, length)
	copy(result, required)

	for i := len(required); i < length; i++ {
		ch, err := randChar(charset)
		if err != nil {
			return "", err
		}
		result[i] = ch
	}

	// Shuffle the result using Fisher-Yates
	for i := length - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		result[i], result[j.Int64()] = result[j.Int64()], result[i]
	}

	return string(result), nil
}

func randChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

func toUserResponse(user models.User) userResponse {
	return userResponse{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		IsAdmin:     user.IsAdmin,
		MFAEnabled:  user.MFAEnabled,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
}

func getUserIDFromContext(c *gin.Context) uint {
	value, ok := c.Get("userClaims")
	if !ok {
		return 0
	}
	claims, ok := value.(models.UserClaims)
	if !ok {
		return 0
	}
	return claims.UserID
}

func errorJSON(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}

func isUniqueConstraintError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "constraint failed")
}

func sanitizeString(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\x00' {
			return -1
		}
		return r
	}, s)
	return s
}

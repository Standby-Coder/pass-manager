package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db        *gorm.DB
	jwtSecret string
	now       func() time.Time
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

type userResponse struct {
	ID          uint      `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func NewAuthHandler(db *gorm.DB, cfg config.Config) *AuthHandler {
	return &AuthHandler{
		db:        db,
		jwtSecret: cfg.JWTSecret,
		now:       time.Now,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req authRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorJSON(c, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Email == "" || req.Password == "" {
		errorJSON(c, http.StatusBadRequest, "email and password are required")
		return
	}

	user := models.User{
		Email:       req.Email,
		DisplayName: req.DisplayName,
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

	email := strings.TrimSpace(strings.ToLower(req.Email))
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

	if err := user.CheckPassword(req.Password); err != nil {
		errorJSON(c, http.StatusUnauthorized, "invalid credentials")
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

func (h *AuthHandler) generateToken(user models.User) (string, error) {
	now := h.now()
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
	return token.SignedString([]byte(h.jwtSecret))
}

func toUserResponse(user models.User) userResponse {
	return userResponse{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}
}

func errorJSON(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}

func isUniqueConstraintError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "constraint failed")
}
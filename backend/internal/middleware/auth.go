package middleware

import (
	"net/http"
	"strings"

	"pass-manager/backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const userClaimsContextKey = "userClaims"

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*models.UserClaims)
		if !ok || !token.Valid || claims.UserID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set(userClaimsContextKey, *claims)
		c.Next()
	}
}

func UserClaimsFromContext(c *gin.Context) models.UserClaims {
	value, ok := c.Get(userClaimsContextKey)
	if !ok {
		return models.UserClaims{}
	}

	claims, ok := value.(models.UserClaims)
	if !ok {
		return models.UserClaims{}
	}

	return claims
}

func UserIDFromContext(c *gin.Context) uint {
	return UserClaimsFromContext(c).UserID
}
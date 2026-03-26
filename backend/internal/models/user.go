package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID             uint            `gorm:"primaryKey" json:"id"`
	Email          string          `gorm:"uniqueIndex;not null;size:255" json:"email"`
	PasswordHash   string          `gorm:"not null" json:"-"`
	DisplayName    string          `gorm:"size:255" json:"display_name"`
	PasswordEntries []PasswordEntry `json:"password_entries,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type UserClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.DisplayName == "" {
		u.DisplayName = u.Email
	}

	return nil
}

func (u *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hashedPassword)
	return nil
}

func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
}
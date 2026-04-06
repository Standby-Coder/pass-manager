package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID               uint            `gorm:"primaryKey" json:"id"`
	Email            string          `gorm:"uniqueIndex;not null;size:255" json:"email"`
	PasswordHash     string          `gorm:"not null" json:"-"`
	DisplayName      string          `gorm:"size:255" json:"display_name"`
	IsAdmin          bool            `gorm:"default:false" json:"is_admin"`
	MFAEnabled       bool            `gorm:"default:false" json:"mfa_enabled"`
	MFACode          string          `gorm:"size:64" json:"-"`
	MFACodeExpiry    *time.Time      `json:"-"`
	FailedAttempts   int             `gorm:"default:0" json:"-"`
	LockedUntil      *time.Time      `json:"-"`
	ResetToken       string          `gorm:"size:64" json:"-"`
	ResetTokenExpiry *time.Time      `json:"-"`
	PasswordEntries  []PasswordEntry `json:"password_entries,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
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

func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

func (u *User) GenerateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	u.ResetToken = token
	expiry := time.Now().Add(1 * time.Hour)
	u.ResetTokenExpiry = &expiry
	return token, nil
}

// GenerateMFACode generates a 6-digit MFA code for email verification.
func (u *User) GenerateMFACode() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", (int(b[0])<<16|int(b[1])<<8|int(b[2]))%1000000)
	u.MFACode = hex.EncodeToString([]byte(code))
	expiry := time.Now().Add(5 * time.Minute)
	u.MFACodeExpiry = &expiry
	return code, nil
}

// VerifyMFACode checks the MFA code against the stored hash.
func (u *User) VerifyMFACode(code string, now time.Time) bool {
	if u.MFACodeExpiry == nil || now.After(*u.MFACodeExpiry) {
		return false
	}
	storedCode, err := hex.DecodeString(u.MFACode)
	if err != nil {
		return false
	}
	return string(storedCode) == code
}

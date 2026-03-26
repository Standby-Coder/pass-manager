package models

import "time"

type PasswordEntry struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	UserID      uint      `gorm:"index;not null" json:"user_id"`
	Title       string    `gorm:"not null;size:255" json:"title"`
	Username    string    `gorm:"size:255" json:"username"`
	Password    string    `gorm:"not null" json:"password"`
	URL         string    `gorm:"size:512" json:"url"`
	Notes       string    `gorm:"type:text" json:"notes"`
	Category    string    `gorm:"size:100" json:"category"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
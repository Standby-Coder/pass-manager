package models

import "time"

type PasswordEntry struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	UserID      uint       `gorm:"index;not null" json:"user_id"`
	ClientID    string     `gorm:"size:64;index" json:"client_id,omitempty"`
	Title       string     `gorm:"not null;size:255" json:"title"`
	Username    string     `gorm:"size:255" json:"username"`
	Password    string     `gorm:"not null" json:"password"`
	URL         string     `gorm:"size:512" json:"url"`
	Notes       string     `gorm:"type:text" json:"notes"`
	Category    string     `gorm:"size:100" json:"category"`
	SyncVersion int64      `gorm:"default:1" json:"sync_version"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	IsDeleted   bool       `gorm:"default:false" json:"is_deleted,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

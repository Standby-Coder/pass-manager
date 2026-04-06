package models

import "time"

type AppSetting struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Key       string    `gorm:"uniqueIndex;not null;size:100" json:"key"`
	Value     string    `gorm:"not null;size:500" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

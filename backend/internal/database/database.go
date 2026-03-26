package database

import (
	"os"
	"path/filepath"

	"pass-manager/backend/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func New(databasePath string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(databasePath), os.ModePerm); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&models.User{}, &models.PasswordEntry{}); err != nil {
		return nil, err
	}

	return db, nil
}
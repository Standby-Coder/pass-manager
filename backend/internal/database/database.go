package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// New creates a new database connection and runs migrations.
// If dbEncryptionKey is provided and an encrypted DB file exists, it will be decrypted first.
func New(databasePath, dbEncryptionKey string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(databasePath), os.ModePerm); err != nil {
		return nil, err
	}

	encPath := databasePath + ".enc"

	// If an encrypted DB exists but plain doesn't, decrypt it
	if dbEncryptionKey != "" {
		if _, err := os.Stat(encPath); err == nil {
			if _, err := os.Stat(databasePath); os.IsNotExist(err) {
				log.Println("Decrypting database file...")
				if err := crypto.DecryptFile(encPath, databasePath, dbEncryptionKey); err != nil {
					return nil, fmt.Errorf("failed to decrypt database: %w", err)
				}
				os.Remove(encPath)
			}
		}
	}

	db, err := gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&models.User{},
		&models.PasswordEntry{},
		&models.AppSetting{},
	); err != nil {
		return nil, err
	}

	return db, nil
}

// EncryptOnShutdown encrypts the DB file for at-rest protection.
func EncryptOnShutdown(databasePath, dbEncryptionKey string) {
	if dbEncryptionKey == "" {
		return
	}

	encPath := databasePath + ".enc"
	log.Println("Encrypting database file for at-rest protection...")

	if err := crypto.EncryptFile(databasePath, encPath, dbEncryptionKey); err != nil {
		log.Printf("WARNING: failed to encrypt database: %v", err)
		return
	}

	if err := os.Remove(databasePath); err != nil {
		log.Printf("WARNING: failed to remove plain database: %v", err)
	}
}

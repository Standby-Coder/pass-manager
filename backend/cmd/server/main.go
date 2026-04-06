package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/crypto"
	"pass-manager/backend/internal/database"
	"pass-manager/backend/internal/models"
	"pass-manager/backend/internal/router"

	"github.com/spf13/cobra"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "pass-manager",
	Short: "A secure password manager server",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the password manager server",
	RunE:  runServe,
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt the database and output all data as JSON",
	Long:  "Decrypts the encrypted database file and all encrypted password fields, then outputs everything as JSON.",
	RunE:  runDecrypt,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (default: ./config.yaml)")
	decryptCmd.Flags().StringP("output", "o", "", "output file path (default: stdout)")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(decryptCmd)

	// Make serve the default command
	rootCmd.RunE = runServe
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	config.InitViper(cfgFile)
	cfg := config.Load()
	cfg.WarnInsecureDefaults()

	db, err := database.New(cfg.DatabasePath, cfg.DBEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Set up graceful shutdown to encrypt DB
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		database.EncryptOnShutdown(cfg.DatabasePath, cfg.DBEncryptionKey)
		os.Exit(0)
	}()

	r := router.Setup(db, cfg)

	log.Printf("Starting server on %s", cfg.ServerAddress())
	if err := r.Run(cfg.ServerAddress()); err != nil {
		database.EncryptOnShutdown(cfg.DatabasePath, cfg.DBEncryptionKey)
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

type exportEntry struct {
	ID        uint      `json:"id"`
	ClientID  string    `json:"client_id,omitempty"`
	Title     string    `json:"title"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	URL       string    `json:"url"`
	Notes     string    `json:"notes"`
	Category  string    `json:"category"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type exportUser struct {
	ID          uint          `json:"id"`
	Email       string        `json:"email"`
	DisplayName string        `json:"display_name"`
	IsAdmin     bool          `json:"is_admin"`
	MFAEnabled  bool          `json:"mfa_enabled"`
	Entries     []exportEntry `json:"entries"`
	CreatedAt   time.Time     `json:"created_at"`
}

type exportData struct {
	ExportedAt time.Time    `json:"exported_at"`
	Users      []exportUser `json:"users"`
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	config.InitViper(cfgFile)
	cfg := config.Load()

	dbPath := cfg.DatabasePath
	encPath := dbPath + ".enc"
	tmpPath := ""

	// Check if encrypted version exists
	if _, err := os.Stat(encPath); err == nil {
		if cfg.DBEncryptionKey == "" {
			return fmt.Errorf("encrypted database found at %s but DB_ENCRYPTION_KEY is not set", encPath)
		}
		tmpPath = dbPath + ".decrypt-tmp"
		if err := crypto.DecryptFile(encPath, tmpPath, cfg.DBEncryptionKey); err != nil {
			return fmt.Errorf("failed to decrypt database file: %w", err)
		}
		defer os.Remove(tmpPath)
		dbPath = tmpPath
	} else if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("no database found at %s or %s", dbPath, encPath)
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	enc, err := crypto.NewFieldEncryptor(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create field encryptor: %w", err)
	}

	var users []models.User
	db.Find(&users)

	export := exportData{
		ExportedAt: time.Now().UTC(),
	}

	for _, u := range users {
		eu := exportUser{
			ID:          u.ID,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			IsAdmin:     u.IsAdmin,
			MFAEnabled:  u.MFAEnabled,
			CreatedAt:   u.CreatedAt,
		}

		var entries []models.PasswordEntry
		db.Where("user_id = ? AND is_deleted = ?", u.ID, false).Find(&entries)

		for _, e := range entries {
			password, _ := enc.Decrypt(e.Password)
			eu.Entries = append(eu.Entries, exportEntry{
				ID:        e.ID,
				ClientID:  e.ClientID,
				Title:     e.Title,
				Username:  e.Username,
				Password:  password,
				URL:       e.URL,
				Notes:     e.Notes,
				Category:  e.Category,
				CreatedAt: e.CreatedAt,
				UpdatedAt: e.UpdatedAt,
			})
		}

		export.Users = append(export.Users, eu)
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Database exported to %s\n", outputFile)
		return nil
	}

	fmt.Println(string(data))
	return nil
}

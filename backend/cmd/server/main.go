package main

import (
	"log"

	"pass-manager/backend/internal/config"
	"pass-manager/backend/internal/database"
	"pass-manager/backend/internal/router"
)

func main() {
	cfg := config.Load()

	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	r := router.Setup(db, cfg)

	if err := r.Run(cfg.ServerAddress()); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}
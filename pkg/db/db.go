package db

import (
	"github.com/rs/zerolog/log"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DB struct {
	*gorm.DB
}

func NewDB(cfg *config.Config) *DB {
	db, err := gorm.Open(postgres.Open(cfg.DatabaseConfig.URL), &gorm.Config{})
	if err != nil {
		log.Panic().Err(err).Msg("Failed to connect to the database")
	}
	return &DB{db}
}

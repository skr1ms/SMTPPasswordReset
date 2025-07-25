package migrations

import (
	"os/user"

	"github.com/rs/zerolog/log"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/db"
)

func Init(cfg *config.Config) {
	database := db.NewDB(cfg)

	err := database.AutoMigrate(
		&user.User{},
	)
	if err != nil {
		log.Panic().Err(err).Msg("Failed to run migrations")
	}
}

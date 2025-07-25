package main

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/internal/auth"
	"github.com/skr1ms/SMTPPasswordReset/internal/user"
	"github.com/skr1ms/SMTPPasswordReset/pkg/db"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
)

func main() {
	cfg := config.NewConfig()
	database := db.NewDB(cfg)
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:  "*",
		AllowMethods:  "GET,POST,PUT,DELETE",
		AllowHeaders:  "Origin,Content-Type,Accept",
		ExposeHeaders: "Content-Length",
		MaxAge:        300,
	}))

	app.Use(recover.New())

	// repository
	authRepository := auth.NewAuthRepository(database.DB)

	// service
	jwt := jwt.NewJWT(cfg.AuthConfig.AccessTokenSecret, cfg.AuthConfig.RefreshTokenSecret)
	authService := auth.NewAuthService(authRepository)

	// handler
	auth.NewAuthHandler(app, auth.AuthHandlerDeps{
		Config:         cfg,
		AuthService:    authService,
		AuthRepository: authRepository,
		Logger:         &logger,
		Jwt:            jwt,
	})

	user.NewUserHandler(app, user.UserHandlerDeps{
		UserRepository: user.NewUserRepository(database.DB),
		Logger:         logger,
		// MailSender:     mailSender,
		Jwt:            jwt,
	})

	app.Listen(cfg.ServerConfig.Port)
}

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
	"github.com/skr1ms/SMTPPasswordReset/migrations"
	"github.com/skr1ms/SMTPPasswordReset/pkg/db"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/mail"
	"github.com/skr1ms/SMTPPasswordReset/pkg/recaptcha"
)

func main() {
	cfg := config.NewConfig()
	database := db.NewDB(cfg)
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	migrations.Init(cfg)
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:  "*",
		AllowMethods:  "GET,POST,PUT,DELETE",
		AllowHeaders:  "Origin,Content-Type,Accept",
		ExposeHeaders: "Content-Length",
		MaxAge:        300,
	}))

	app.Use(recover.New())
	api := app.Group("/api")

	// repository
	authRepository := auth.NewAuthRepository(database.DB)
	userRepository := user.NewUserRepository(database.DB)

	// service
	jwt := jwt.NewJWT(cfg.AuthConfig.AccessTokenSecret, cfg.AuthConfig.RefreshTokenSecret)
	mailSender := mail.NewMailer(cfg, &logger)
	recaptcha := recaptcha.NewVerifier(cfg.RecaptchaConfig.SecretKey, 0.5)
	authService := auth.NewAuthService(authRepository, jwt)
	userService := user.NewUserService(userRepository, recaptcha, jwt, mailSender, cfg)

	// handler
	auth.NewAuthHandler(api, auth.AuthHandlerDeps{
		Config:      cfg,
		AuthService: authService,
		Logger:      &logger,
	})

	user.NewUserHandler(api, user.UserHandlerDeps{
		Config:      cfg,
		UserService: userService,
		Logger:      &logger,
	})

	app.Listen(":" + cfg.ServerConfig.Port)
}

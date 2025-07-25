package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/req"
)

type AuthHandlerDeps struct {
	Config         *config.Config
	AuthRepository *AuthRepository
	AuthService    *AuthService
	Logger         *zerolog.Logger
	Jwt            *jwt.JWT
}

type AuthHandler struct {
	fiber.Router
	deps AuthHandlerDeps
}

func NewAuthHandler(router fiber.Router, deps AuthHandlerDeps) {
	handler := &AuthHandler{
		Router: router,
		deps:   deps,
	}

	authRoutes := handler.Group("/auth")
	authRoutes.Post("/register", handler.Register)
	authRoutes.Post("/login", handler.Login)
	authRoutes.Post("/refresh", handler.RefreshTokens)
}

func (handler *AuthHandler) Register(c *fiber.Ctx) error {
	var payload LoginRequest
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := req.IsValid(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Validation failed", "details": err.Error()})
	}

	err := handler.deps.AuthService.Register(payload.Email, payload.Password)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg("Failed to register user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func (handler *AuthHandler) Login(c *fiber.Ctx) error {
	var payload LoginRequest
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request payload"})
	}

	if err := req.IsValid(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Validation failed", "details": err.Error()})
	}

	user, err := handler.deps.AuthService.Login(payload.Email, payload.Password)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg("Failed to login user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to login"})
	}
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	tokens, err := handler.deps.Jwt.CreateTokenPair(user.Id, user.Email)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg("Failed to create tokens")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create tokens"})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (handler *AuthHandler) RefreshTokens(c *fiber.Ctx) error {
	var req RefreshTokenRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	tokenPair, err := handler.deps.Jwt.RefreshTokens(req.RefreshToken)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg("Failed to refresh tokens")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired refresh token"})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

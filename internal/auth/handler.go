package auth

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/req"
)

type AuthHandlerDeps struct {
	Config      *config.Config
	AuthService *AuthService
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
	log := zerolog.Ctx(c.UserContext())
	var reqPayload RegisterRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to parse request body: %w", err).Error(),
		})
	}

	if err := req.IsValid(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("validation failed: %w", err).Error(),
		})
	}

	err := handler.deps.AuthService.Register(reqPayload.Email, reqPayload.Password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to register")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to register: %w", err).Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func (handler *AuthHandler) Login(c *fiber.Ctx) error {
	log := zerolog.Ctx(c.UserContext())
	var reqPayload LoginRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to parse request body: %w", err).Error(),
		})
	}

	if err := req.IsValid(reqPayload); err != nil {
		log.Error().Err(err).Msg("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("validation failed: %w", err).Error(),
		})
	}

	tokens, err := handler.deps.AuthService.Login(reqPayload.Email, reqPayload.Password)
	if err != nil {
		log.Error().Err(err).Msg("Failed to login")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to login: %w", err).Error(),
		})
	}

	log.Info().Msg("Login successful")

	return c.JSON(fiber.Map{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (handler *AuthHandler) RefreshTokens(c *fiber.Ctx) error {
	log := zerolog.Ctx(c.UserContext())
	var req RefreshTokenRequest

	if err := c.BodyParser(&req); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to parse request body: %w", err).Error(),
		})
	}

	tokenPair, err := handler.deps.AuthService.RefreshTokens(req.RefreshToken)
	if err != nil {
		log.Error().Err(err).Msg("Invalid refresh token")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": fmt.Errorf("invalid refresh token: %w", err).Error(),
		})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

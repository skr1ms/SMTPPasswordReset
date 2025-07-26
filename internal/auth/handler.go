package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/req"
)

type AuthHandlerDeps struct {
	Config      *config.Config
	AuthService *AuthService
	Logger      *zerolog.Logger
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
	var reqPayload RegisterRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrBadRequest.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrBadRequest.Error()})
	}

	if err := req.IsValid(&reqPayload); err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrValidationFailed.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrValidationFailed.Error()})
	}

	err := handler.deps.AuthService.Register(reqPayload.Email, reqPayload.Password)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrFailedToRegister.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ValidateError(err).Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func (handler *AuthHandler) Login(c *fiber.Ctx) error {
	var reqPayload LoginRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrBadRequest.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrBadRequest.Error()})
	}

	if err := req.IsValid(reqPayload); err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrValidationFailed.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrValidationFailed.Error()})
	}

	tokens, err := handler.deps.AuthService.Login(reqPayload.Email, reqPayload.Password)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrFailedToLogin.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ValidateError(err).Error()})
	}

	handler.deps.Logger.Info().Msg("Login successful")

	return c.JSON(fiber.Map{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (handler *AuthHandler) RefreshTokens(c *fiber.Ctx) error {
	var req RefreshTokenRequest

	if err := c.BodyParser(&req); err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrBadRequest.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	tokenPair, err := handler.deps.AuthService.RefreshTokens(req.RefreshToken)
	if err != nil {
		handler.deps.Logger.Error().Err(err).Msg(ErrInvalidRefreshToken.Error())
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": ValidateError(err).Error()})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_in":    tokenPair.ExpiresIn,
	})
}

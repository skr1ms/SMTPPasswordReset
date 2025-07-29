package user

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/req"
)

type UserHandlerDeps struct {
	Config      *config.Config
	UserService *UserService
	Jwt         *jwt.JWT
}

type UserHandler struct {
	fiber.Router
	deps UserHandlerDeps
}

func NewUserHandler(router fiber.Router, deps UserHandlerDeps) {
	handler := &UserHandler{
		Router: router,
		deps:   deps,
	}

	userRoutes := handler.Group("/user")
	userRoutes.Post("/forgot", handler.ForgotPassword)
	userRoutes.Post("/reset", handler.ResetPassword)
}

// ForgotPassword обрабатывает запрос на сброс пароля
func (h *UserHandler) ForgotPassword(c *fiber.Ctx) error {
	log := zerolog.Ctx(c.UserContext())
	var reqPayload ForgotPasswordRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to parse request body: %w", err).Error(),
		})
	}

	if err := req.IsValid(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   fmt.Errorf("validation failed: %w", err).Error(),
			"details": err.Error(),
		})
	}

	if h.deps.Config.RecaptchaConfig.Environment == "development" {
		log.Warn().Msg("reCAPTCHA verification is disabled in development mode")
	} else {
		// valid, err := h.deps.UserService.Recaptcha.Verify(reqPayload.Captcha, "forgot_password")
		// if err != nil || !valid {
		// 	return ErrInvalidCaptcha
		// }
	}

	err := h.deps.UserService.ForgotPassword(reqPayload.Email /*reqPayload.Captcha*/)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send email")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to send email: %w", err).Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "If email exists, email sent",
	})
}

// ResetPassword обрабатывает установку нового пароля
func (h *UserHandler) ResetPassword(c *fiber.Ctx) error {
	log := zerolog.Ctx(c.UserContext())
	var reqPayload ResetPasswordRequest
	if err := c.BodyParser(&reqPayload); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to parse request body: %w", err).Error(),
		})
	}

	if err := req.IsValid(reqPayload); err != nil {
		log.Error().Err(err).Msg("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   fmt.Errorf("validation failed: %w", err).Error(),
			"details": err.Error(),
		})
	}

	err := h.deps.UserService.ResetPassword(reqPayload.Token, reqPayload.NewPassword)
	if err != nil {
		log.Error().Err(err).Msg("Failed to reset password")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Errorf("failed to reset password: %w", err).Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Password successfully changed",
	})
}

package user

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/bcrypt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/mail"
	"github.com/skr1ms/SMTPPasswordReset/pkg/req"
)

type UserHandlerDeps struct {
	Config         *config.Config
	UserRepository *UserRepository
	Logger         zerolog.Logger
	MailSender     *mail.Mailer
	Jwt            *jwt.JWT
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
	userRoutes.Get("/:id", handler.ForgotPassword)
	userRoutes.Post("/reset-password", handler.ResetPassword)
}

// ForgotPassword обрабатывает запрос на сброс пароля
func (handler *UserHandler) ForgotPassword(c *fiber.Ctx) error {
	var payload ForgotPasswordRequest
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	if err := req.IsValid(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid email address",
		})
	}

	user, err := handler.deps.UserRepository.GetUserByEmail(payload.Email)
	if err != nil || user == nil {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"message": "If the email exists, a reset link has been sent",
		})
	}

	// Генерируем JWT токен для сброса пароля
	resetToken, err := handler.deps.Jwt.CreatePasswordResetToken(user.Id, user.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate reset token",
		})
	}

	// Формируем ссылку для сброса
	resetLink := fmt.Sprintf("http://localhost:%s/api/user/reset-password?token=%s",
		handler.deps.Config.ServerConfig.Port,
		resetToken,
	)

	// Отправляем email
	if err := handler.deps.MailSender.SendResetPasswordEmail(user.Email, resetLink); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to send reset email",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "If the email exists, a reset link has been sent",
	})
}

// ResetPassword обрабатывает установку нового пароля
func (handler *UserHandler) ResetPassword(c *fiber.Ctx) error {
	var payload ResetPasswordRequest
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request format",
		})
	}

	if err := req.IsValid(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Validation failed",
			"details": err.Error(),
		})
	}

	// Проверяем токен сброса
	claims, err := handler.deps.Jwt.ValidatePasswordResetToken(payload.Token)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid or expired reset token",
		})
	}

	hashedPassword, err := bcrypt.HashPassword(payload.NewPassword)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	if err := handler.deps.UserRepository.UpdatePassword(claims.UserID, hashedPassword); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update password",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Password has been reset successfully",
	})
}

package user

import (
	"fmt"

	"github.com/skr1ms/SMTPPasswordReset/config"
	"github.com/skr1ms/SMTPPasswordReset/pkg/bcrypt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/mail"
	"github.com/skr1ms/SMTPPasswordReset/pkg/recaptcha"
)

type UserService struct {
	UserRepository *UserRepository
	Recaptcha      *recaptcha.Verifier
	Jwt            *jwt.JWT
	MailSender     *mail.Mailer
	Config         *config.Config
}

func NewUserService(userRepository *UserRepository, recaptcha *recaptcha.Verifier, jwt *jwt.JWT, mailSender *mail.Mailer, config *config.Config) *UserService {
	return &UserService{
		UserRepository: userRepository,
		Recaptcha:      recaptcha,
		Jwt:            jwt,
		MailSender:     mailSender,
		Config:         config,
	}
}

func (s *UserService) ForgotPassword(email string /*captcha string*/) error {
	user, err := s.UserRepository.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Валидация reCAPTCHA
	// valid, err := s.Recaptcha.Verify(captcha, "forgot_password")
	// if err != nil || !valid {
	// 	return ErrInvalidCaptcha
	// }

	resetToken, err := s.Jwt.CreatePasswordResetToken(user.Id, user.Email)
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	resetLink := fmt.Sprintf("%s/reset?token=%s",
		s.Config.ServerConfig.FrontendURL,
		resetToken,
	)

	if err := s.MailSender.SendResetPasswordEmail(user.Email, resetLink); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

func (s *UserService) ResetPassword(token, newPassword string) error {
	claims, err := s.Jwt.ValidatePasswordResetToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	hashedPassword, err := bcrypt.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := s.UserRepository.UpdatePassword(claims.UserID, hashedPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

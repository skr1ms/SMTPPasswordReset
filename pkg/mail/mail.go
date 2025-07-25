package mail

import (
	"fmt"
	"net/smtp"

	"github.com/skr1ms/SMTPPasswordReset/config"
)

type Mailer struct {
	cfg *config.Config
}

func NewMailer(cfg *config.Config) *Mailer {
	return &Mailer{cfg: cfg}
}

func (m *Mailer) SendResetPasswordEmail(to, resetLink string) error {
	auth := smtp.PlainAuth("", m.cfg.SMTPConfig.Username, m.cfg.SMTPConfig.Password, m.cfg.SMTPConfig.Host)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: Password Reset\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n\r\n"+
			"<h2>Password Reset</h2>"+
			"<p>Click the link to reset your password:</p>"+
			"<a href=\"%s\">Reset Password</a>"+
			"<p>Link expires in 1 hour.</p>",
		m.cfg.SMTPConfig.From, to, resetLink,
	))

	return smtp.SendMail(
		fmt.Sprintf("%s:%d", m.cfg.SMTPConfig.Host, m.cfg.SMTPConfig.Port),
		auth,
		m.cfg.SMTPConfig.From,
		[]string{to},
		msg,
	)
}

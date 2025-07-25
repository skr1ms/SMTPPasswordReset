package user

// ForgotPasswordRequest структура для запроса на сброс пароля
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest структура для запроса на обновление пароля
type ResetPasswordRequest struct {
	Token    string `json:"token" validate:"required"`
	NewPassword string `json:"password" validate:"required,min=8"`
}
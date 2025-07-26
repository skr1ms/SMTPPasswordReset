package user

import "errors"

var (
	ErrUserNotFound            = errors.New("user not found")
	ErrInvalidCaptcha          = errors.New("invalid captcha")
	ErrFailedToCreateToken     = errors.New("failed to create token")
	ErrFailedToSendEmail       = errors.New("failed to send email")
	ErrFailedToHashPassword    = errors.New("failed to hash password")
	ErrFailedToUpdatePassword  = errors.New("failed to update password")
	ErrInvalidToken            = errors.New("invalid token")
	ErrBadRequest              = errors.New("bad request")
	ErrValidationFailed        = errors.New("validation failed")
	ErrFailedToFindUserByEmail = errors.New("failed to find user by email")
	ErrFailedToCreateUser      = errors.New("failed to create user")
	ErrFailedToFindUserByID    = errors.New("failed to find user by id")
)

func ValidateError(err error) error {
	switch err {
	case ErrUserNotFound:
		return ErrUserNotFound
	case ErrInvalidCaptcha:
		return ErrInvalidCaptcha
	case ErrFailedToCreateToken:
		return ErrFailedToCreateToken
	case ErrFailedToSendEmail:
		return ErrFailedToSendEmail
	case ErrFailedToHashPassword:
		return ErrFailedToHashPassword
	case ErrFailedToUpdatePassword:
		return ErrFailedToUpdatePassword
	case ErrInvalidToken:
		return ErrInvalidToken
	case ErrBadRequest:
		return ErrBadRequest
	case ErrValidationFailed:
		return ErrValidationFailed
	case ErrFailedToFindUserByEmail:
		return ErrFailedToFindUserByEmail
	case ErrFailedToCreateUser:
		return ErrFailedToCreateUser
	case ErrFailedToFindUserByID:
		return ErrFailedToFindUserByID
	}
	return err
}

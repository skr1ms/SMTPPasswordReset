package auth

import "errors"

var (
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrUserNotFound            = errors.New("user not found")
	ErrUserAlreadyExists       = errors.New("user already exists")
	ErrInvalidToken            = errors.New("invalid token")
	ErrFailedToCreateTokens    = errors.New("failed to create tokens")
	ErrFailedToRegisterUser    = errors.New("failed to register user")
	ErrValidationFailed        = errors.New("validation failed")
	ErrBadRequest              = errors.New("bad request")
	ErrInvalidRefreshToken     = errors.New("invalid refresh token")
	ErrFailedToHashPassword    = errors.New("failed to hash password")
	ErrFailedToLogin           = errors.New("failed to login")
	ErrFailedToRegister        = errors.New("failed to register")
	ErrFailedToFindUserByEmail = errors.New("failed to find user by email")
	ErrFailedToCreateUser      = errors.New("failed to create user")
)

func ValidateError(err error) error {
	switch err {
	case ErrInvalidCredentials:
		return ErrInvalidCredentials
	case ErrUserNotFound:
		return ErrUserNotFound
	case ErrUserAlreadyExists:
		return ErrUserAlreadyExists
	case ErrInvalidToken:
		return ErrInvalidToken
	case ErrFailedToCreateTokens:
		return ErrFailedToCreateTokens
	case ErrFailedToRegisterUser:
		return ErrFailedToRegisterUser
	case ErrValidationFailed:
		return ErrValidationFailed
	case ErrBadRequest:
		return ErrBadRequest
	case ErrInvalidRefreshToken:
		return ErrInvalidRefreshToken
	case ErrFailedToHashPassword:
		return ErrFailedToHashPassword
	case ErrFailedToLogin:
		return ErrFailedToLogin
	case ErrFailedToRegister:
		return ErrFailedToRegister
	case ErrFailedToFindUserByEmail:
		return ErrFailedToFindUserByEmail
	case ErrFailedToCreateUser:
		return ErrFailedToCreateUser
	}
	return err
}

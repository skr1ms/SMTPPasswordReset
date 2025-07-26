package auth

import (
	"github.com/skr1ms/SMTPPasswordReset/internal/user"
	"github.com/skr1ms/SMTPPasswordReset/pkg/bcrypt"
	"github.com/skr1ms/SMTPPasswordReset/pkg/jwt"
)

type AuthService struct {
	AuthRepository *AuthRepository
	Jwt            *jwt.JWT
}

func NewAuthService(repo *AuthRepository, jwt *jwt.JWT) *AuthService {
	return &AuthService{
		AuthRepository: repo,
		Jwt:            jwt,
	}
}

func (s *AuthService) Register(email, password string) error {
	userExists, err := s.AuthRepository.FindUserByEmail(email)
	if err != nil {
		return ErrUserAlreadyExists
	}
	if userExists != nil {
		return ErrUserAlreadyExists
	}

	password, err = bcrypt.HashPassword(password)
	if err != nil {
		return ErrFailedToHashPassword
	}

	user := &user.User{
		Email:    email,
		Password: password,
	}
	return s.AuthRepository.CreateUser(user)
}

func (s *AuthService) Login(email, password string) (*jwt.TokenPair, error) {
	user, err := s.AuthRepository.FindUserByEmail(email)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CheckPassword(user.Password, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	tokens, err := s.Jwt.CreateTokenPair(user.Id, user.Email)
	if err != nil {
		return nil, ErrFailedToCreateTokens
	}

	return tokens, nil
}

func (s *AuthService) RefreshTokens(refreshToken string) (*jwt.TokenPair, error) {
	tokenPair, err := s.Jwt.RefreshTokens(refreshToken)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}
	return tokenPair, nil
}

package auth

import (
	"github.com/skr1ms/SMTPPasswordReset/internal/user"
	"github.com/skr1ms/SMTPPasswordReset/pkg/bcrypt"
)

type AuthService struct {
	AuthRepository *AuthRepository
}

func NewAuthService(repo *AuthRepository) *AuthService {
	return &AuthService{
		AuthRepository: repo,
	}
}

func (s *AuthService) Register(email, password string) error {
	userExists, err := s.AuthRepository.FindUserByEmail(email)
	if err != nil {
		return err
	}
	if userExists != nil {
		return nil
	}

	password, err = bcrypt.HashPassword(password)

	user := &user.User{
		Email:    email,
		Password: password, // In a real application, ensure to hash the password
	}
	return s.AuthRepository.CreateUser(user)
}

func (s *AuthService) Login(email, password string) (*user.User, error) {
	user, err := s.AuthRepository.FindUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Password != password {
		return nil, nil
	}

	if err := bcrypt.CheckPassword(user.Password, password); err != nil {
		return nil, err
	}
	
	return user, nil
}

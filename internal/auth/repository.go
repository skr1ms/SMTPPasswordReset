package auth

import (
	"errors"
	"fmt"

	"github.com/skr1ms/SMTPPasswordReset/internal/user"
	"gorm.io/gorm"
)

type AuthRepository struct {
	DB *gorm.DB
}

func NewAuthRepository(db *gorm.DB) *AuthRepository {
	return &AuthRepository{
		DB: db,
	}
}

func (repo *AuthRepository) FindUserByEmail(email string) (*user.User, error) {
	var user user.User
	if err := repo.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}
	return &user, nil
}

func (repo *AuthRepository) CreateUser(user *user.User) error {
	if err := repo.DB.Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

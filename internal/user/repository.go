package user

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRepository struct {
	DB *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{
		DB: db,
	}
}
func (repo *UserRepository) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := repo.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}
	return &user, nil
}

func (repo *UserRepository) UpdatePassword(userID uuid.UUID, newPassword string) error {
	var user User
	if err := repo.DB.First(&user, userID).Error; err != nil {
		return fmt.Errorf("failed to find user by id: %w", err)
	}

	user.Password = newPassword
	if err := repo.DB.Save(&user).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	return nil
}

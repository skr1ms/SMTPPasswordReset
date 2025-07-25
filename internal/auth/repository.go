package auth

import (
	"gorm.io/gorm"
	"github.com/skr1ms/SMTPPasswordReset/internal/user"
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
		if err == gorm.ErrRecordNotFound {
			return nil, nil 
		}
		return nil, err 
	}
	return &user, nil
}

func (repo *AuthRepository) CreateUser(user *user.User) error {
	if err := repo.DB.Create(user).Error; err != nil {
		return err
	}
	return nil
}

package user

import (
	"github.com/google/uuid"
)

type User struct {
	Id        uuid.UUID `json:"id" gorm:"primaryKey"`
	Email     string    `json:"email" gorm:"uniqueIndex"`
	Password  string    `json:"password"`
	CreatedAt string    `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt string    `json:"updated_at" gorm:"autoUpdateTime"`
}

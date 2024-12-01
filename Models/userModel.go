package models

import "gorm.io/gorm"

type RefreshToken struct {
	gorm.Model
	UserID    string `gorm:"unique"`
	TokenHash string
}

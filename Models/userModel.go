package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
}

// type User struct {
// 	gorm.Model
// 	Email    string `gorm:"unique"`
// 	Password string
// }

type RefreshToken struct {
	gorm.Model
	UserID    string `gorm:"unique"`
	TokenHash string
	// AssociatedIP string
}

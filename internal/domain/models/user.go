package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	ID       int64  `gorm:"primary_key"`
	Email    string `gorm:"unique"`
	PassHash []byte
	IsAdmin  bool
}

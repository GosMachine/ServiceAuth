package models

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	ID            int    `gorm:"primary_key"`
	Email         string `gorm:"uniqueIndex"`
	EmailVerified bool   `gorm:"index"`
	PassHash      []byte
	IpCreated     string
	LastLoginIp   string
	Balance       float64
	LastLoginDate time.Time `gorm:"default:CURRENT_TIMESTAMP"`
}

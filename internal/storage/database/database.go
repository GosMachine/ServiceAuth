package database

import (
	"fmt"
	"github.com/GosMachine/ServiceAuth/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
)

type database struct {
	db *gorm.DB
}

type Database interface {
	CreateUser(email, ip string, passHash []byte, emailVerified bool) error
	User(email string) (models.User, error)
	EmailVerified(email string) (bool, error)
	EmailVerify(email string) error
	UpdateUser(user models.User) error
	DeleteUser(email string) error
}

func New() (Database, error) {
	connection := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_DATABASE"))
	db, err := gorm.Open(postgres.Open(connection), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	err = db.AutoMigrate(&models.User{})
	if err != nil {
		return nil, err
	}
	return &database{db: db}, nil
}

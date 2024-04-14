package postgres

import (
	"fmt"
	"github.com/GosMachine/ServiceAuth/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
)

type Database struct {
	db *gorm.DB
}

func New() (*Database, error) {
	connection := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_PORT"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"))
	database, err := gorm.Open(postgres.Open(connection), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	err = database.AutoMigrate(&models.User{})
	if err != nil {
		return nil, err
	}
	return &Database{db: database}, nil
}

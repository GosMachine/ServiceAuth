package postgres

import (
	"fmt"
	"os"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/domain/models"
	"github.com/GosMachine/ServiceAuth/internal/storage"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Storage struct {
	db *gorm.DB
}

func New() (*Storage, error) {
	connection := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_PORT"), os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_DB"))
	database, err := gorm.Open(postgres.Open(connection), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	err = database.AutoMigrate(&models.User{})
	if err != nil {
		return nil, err
	}
	return &Storage{db: database}, nil
}

func (s *Storage) SaveUser(email, ip string, passHash []byte, emailVerified bool) error {
	const op = "storage.postgres.SaveUser"
	user := models.User{Email: email, PassHash: passHash, IpCreated: ip, LastLoginIp: ip, LastLoginDate: time.Now(), EmailVerified: emailVerified}
	if err := s.db.Create(&user).Error; err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (s *Storage) User(email string) (models.User, error) {
	const op = "storage.postgres.User"

	var user models.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}
	return user, nil
}

func (s *Storage) UpdateUser(user models.User) error {
	result := s.db.Save(&user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

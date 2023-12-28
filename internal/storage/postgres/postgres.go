package postgres

import (
	"ServiceAuth/internal/domain/models"
	"ServiceAuth/internal/storage"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Storage struct {
	db *gorm.DB
}

func New() (*Storage, error) {
	connection := "user=postgres password=postgres dbname=AuthDB host=127.0.0.1 sslmode=disable"
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

func (s *Storage) SaveUser(email string, passHash []byte) (int64, error) {
	const op = "storage.postgres.SaveUser"
	user := models.User{Email: email, PassHash: passHash}
	if err := s.db.Create(&user).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
	}
	return user.ID, nil
}

func (s *Storage) User(email string) (models.User, error) {
	const op = "storage.postgres.User"

	var user models.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}
	return user, nil
}

func (s *Storage) IsAdmin(userID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	var user models.User
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}
	return user.IsAdmin, nil
}

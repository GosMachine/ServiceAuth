package database

import (
	"errors"
	"time"

	"github.com/GosMachine/ServiceAuth/internal/models"
	"github.com/GosMachine/ServiceAuth/internal/storage"
	"gorm.io/gorm"
)

func (d *database) CreateUser(email, ip string, passHash []byte, emailVerified bool) error {
	user := models.User{Email: email, PassHash: passHash, IpCreated: ip, LastLoginIp: ip, LastLoginDate: time.Now(), EmailVerified: emailVerified}
	if err := d.db.Create(&user).Error; err != nil {
		return storage.ErrUserExists
	}
	return nil
}

func (d *database) User(email string) (models.User, error) {
	var user models.User
	if err := d.db.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, storage.ErrUserNotFound
	}
	return user, nil
}

func (d *database) EmailVerified(email string) (bool, error) {
	var user models.User
	if err := d.db.Where("email = ?", email).Select("email_verified").First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, storage.ErrUserNotFound
		}
		return false, err
	}
	return user.EmailVerified, nil
}

func (d *database) EmailVerify(email string) error {
	return d.db.Model(&models.User{}).Where("email = ?", email).Update("email_verified", true).Error
}

func (d *database) UpdateUser(user models.User) error {
	return d.db.Save(&user).Error
}

func (d *database) DeleteUser(email string) error {
	if d.db.Where("email = ?", email).Delete(&models.User{}).Error != nil {
		return storage.ErrUserNotFound
	}
	return nil
}

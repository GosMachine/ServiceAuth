package postgres

import (
	"errors"
	"time"

	storage "github.com/GosMachine/ServiceAuth/internal/database"
	"github.com/GosMachine/ServiceAuth/internal/models"
	"gorm.io/gorm"
)

func (d *Database) CreateUser(email, ip string, passHash []byte, emailVerified bool) error {
	user := models.User{Email: email, PassHash: passHash, IpCreated: ip, LastLoginIp: ip, LastLoginDate: time.Now(), EmailVerified: emailVerified}
	if err := d.db.Create(&user).Error; err != nil {
		return storage.ErrUserExists
	}
	return nil
}

func (d *Database) User(email string) (models.User, error) {
	var user models.User
	if err := d.db.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, storage.ErrUserNotFound
	}
	return user, nil
}

func (d *Database) EmailVerified(email string) (bool, error) {
	var user models.User
	if err := d.db.Where("email = ?", email).Select("email_verified").First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, storage.ErrUserNotFound
		}
		return false, err
	}
	return user.EmailVerified, nil
}

func (d *Database) EmailVerify(email string) error {
	return d.db.Where("email = ?", email).Set("email_verified", true).Error
}

func (d *Database) UpdateUser(user models.User) error {
	return d.db.Save(&user).Error
}

func (d *Database) DeleteUser(email string) error {
	if d.db.Where("email = ?", email).Delete(&models.User{}).Error != nil {
		return storage.ErrUserNotFound
	}
	return nil
}

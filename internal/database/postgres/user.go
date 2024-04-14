package postgres

import (
	"github.com/GosMachine/ServiceAuth/internal/domain/models"
	"time"
)

func (d *Database) CreateUser(email, ip string, passHash []byte, emailVerified bool) error {
	user := models.User{Email: email, PassHash: passHash, IpCreated: ip, LastLoginIp: ip, LastLoginDate: time.Now(), EmailVerified: emailVerified}
	if err := d.db.Create(&user).Error; err != nil {
		return ErrUserExists
	}
	return nil
}

func (d *Database) User(email string) (models.User, error) {
	var user models.User
	if err := d.db.Where("email = ?", email).First(&user).Error; err != nil {
		return models.User{}, ErrUserNotFound
	}
	return user, nil
}

func (d *Database) UpdateUser(user models.User) error {
	return d.db.Save(&user).Error
}

func (d *Database) DeleteUser(email string) error {
	if d.db.Where("email = ?", email).Delete(&models.User{}).Error != nil {
		return ErrUserNotFound
	}
	return nil
}

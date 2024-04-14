package utils

import (
	"regexp"
)

func ValidateAuthData(email, password string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,8}$`)
	passwordRegex := regexp.MustCompile(`^[A-Za-z\d@$!%*?&]{8,}$`)
	if !emailRegex.MatchString(email) {
		return false
	}
	if !passwordRegex.MatchString(password) {
		return false
	}
	return true
}

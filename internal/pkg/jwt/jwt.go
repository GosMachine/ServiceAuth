package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

func NewToken(email, rememberMe string, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	if rememberMe == "on" {
		claims["exp"] = time.Now().Add(3 * 30 * 24 * time.Hour).Unix()
	} else {
		claims["exp"] = time.Now().Add(duration).Unix()
	}
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

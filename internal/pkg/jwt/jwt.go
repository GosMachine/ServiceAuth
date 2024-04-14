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

// returning email if token valid
func IsTokenValid(token string) string {
	tokenData, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil || !tokenData.Valid {
		return ""
	}
	claims, ok := tokenData.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}
	email, ok := claims["email"].(string)
	if !ok {
		return ""
	}
	return email
}

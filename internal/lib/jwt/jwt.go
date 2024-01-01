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
		claims["exp"] = time.Now().Add(time.Hour * 336).Unix()
	} else {
		claims["exp"] = time.Now().Add(duration).Unix()
	}
	claims["remember"] = rememberMe
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func IsTokenValid(token string) (bool, *jwt.Token) {
	tokenData, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if err != nil {
		return false, nil
	}
	return true, tokenData
}

func UpdateToken(tokenData *jwt.Token) (string, error) {
	claims := tokenData.Claims.(jwt.MapClaims)
	email := claims["email"].(string)
	rememberMe := claims["remember"].(string)
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if exp.Sub(time.Now()) <= 48*time.Hour && rememberMe == "on" {
		token, err := NewToken(email, rememberMe, time.Duration(time.Now().Add(time.Hour*336).Unix()))
		if err != nil {
			return "", err
		}
		return token, nil
	}
	return "", nil
}

package utils

import "math/rand"

func GenerateRandomString(length int) string {
	characters := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charactersLen := len(characters)
	result := make([]byte, length)
	for i := range result {
		result[i] = characters[rand.Intn(charactersLen)]
	}
	return string(result)
}

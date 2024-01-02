package validate

import (
	"fmt"
	authv1 "github.com/GosMachine/protos/gen/go/auth"
	"github.com/go-playground/validator/v10"
	"regexp"
)

type User struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

func Login(req *authv1.LoginRequest) error {
	validate := validator.New()
	err := validate.Struct(User{Email: req.GetEmail(), Password: req.GetPassword()})
	if err != nil {
		return fmt.Errorf("invalid email or password")
	}
	return nil
}

func Register(req *authv1.RegisterRequest) error {
	validate := validator.New()
	err := validate.Struct(User{Email: req.GetEmail(), Password: req.GetEmail()})
	if err != nil {
		return fmt.Errorf("invalid email")
	}
	if !validPassword(req.GetPassword()) {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func validPassword(password string) bool {
	regex := regexp.MustCompile(`^[A-Za-z\d@$!%*?&]{8,}$`)
	if !regex.MatchString(password) {
		return false
	}
	return true
}

package validate

import (
	"fmt"
	authv1 "github.com/GosMachine/protos/gen/go/auth"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	err := validate.Struct(User{Email: req.GetEmail()})
	if err != nil {
		return fmt.Errorf("invalid email")
	}
	if !validPassword(req.GetPassword()) {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func IsAdmin(req *authv1.IsAdminRequest) error {
	if req.GetUserId() == 0 {
		return status.Error(codes.InvalidArgument, "user_id is required")
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

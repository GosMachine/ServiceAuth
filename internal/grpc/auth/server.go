package grpcauth

import (
	"ServiceAuth/internal/lib/validator"
	auth "ServiceAuth/internal/services"
	"ServiceAuth/internal/storage"
	"context"
	"errors"
	authv1 "github.com/GosMachine/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(email, password string) (token string, err error)
	RegisterNewUser(email, password string) (userID int64, err error)
	IsAdmin(userID int64) (bool, error)
	IsUserLoggedIn(token string) bool
}

type serverAPI struct {
	authv1.UnimplementedAuthServer
	auth Auth
}

func RegisterAuthServer(gRPC *grpc.Server, auth Auth) {
	authv1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(_ context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if err := validate.Login(req); err != nil {
		return nil, err
	}
	token, err := s.auth.Login(req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}
	return &authv1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(_ context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if err := validate.Register(req); err != nil {
		return nil, err
	}
	userID, err := s.auth.RegisterNewUser(req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register user")
	}
	return &authv1.RegisterResponse{UserId: userID}, nil
}
func (s *serverAPI) IsAdmin(_ context.Context, req *authv1.IsAdminRequest) (*authv1.IsAdminResponse, error) {
	if err := validate.IsAdmin(req); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "failed to check admin status")
	}
	return &authv1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func (s *serverAPI) IsUserLoggedIn(_ context.Context, req *authv1.IsUserLoggedInRequest) (*authv1.IsUserLoggedInResponse, error) {
	IsUserLoggedIn := s.auth.IsUserLoggedIn(req.GetToken())
	return &authv1.IsUserLoggedInResponse{IsUserLoggedIn: IsUserLoggedIn}, nil
}

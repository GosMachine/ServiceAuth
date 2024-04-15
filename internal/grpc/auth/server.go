package grpcauth

import (
	"context"
	"errors"

	storage "github.com/GosMachine/ServiceAuth/internal/database"
	auth "github.com/GosMachine/ServiceAuth/internal/services"
	"github.com/GosMachine/ServiceAuth/internal/utils"
	authv1 "github.com/GosMachine/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(email, password, ip, rememberMe string) (token string, err error)
	OAuth(email, ip string) (token string, err error)
	EmailVerified(email string) (verified bool, err error)
	Register(email, password, ip, rememberMe string) (token string, err error)
}

type serverAPI struct {
	authv1.UnimplementedAuthServer
	auth Auth
}

func RegisterAuthServer(gRPC *grpc.Server, auth Auth) {
	authv1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if !utils.ValidateAuthData(req.Email, req.Password) {
		return nil, status.Error(codes.InvalidArgument, "invalid email or password")
	}
	token, err := s.auth.Login(req.Email, req.Password, req.IP, req.RememberMe)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &authv1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if !utils.ValidateAuthData(req.Email, req.Password) {
		return nil, status.Error(codes.InvalidArgument, "invalid email or password")
	}
	token, err := s.auth.Register(req.Email, req.Password, req.IP, req.RememberMe)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register user")
	}
	return &authv1.RegisterResponse{Token: token}, nil
}

func (s *serverAPI) OAuth(ctx context.Context, req *authv1.OAuthRequest) (*authv1.OAuthResponse, error) {
	token, err := s.auth.OAuth(req.Email, req.IP)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to OAuth")
	}
	return &authv1.OAuthResponse{Token: token}, nil
}

func (s *serverAPI) EmailVerified(ctx context.Context, req *authv1.EmailVerifiedRequest) (*authv1.EmailVerifiedResponse, error) {
	verified, err := s.auth.EmailVerified(req.Email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.EmailVerifiedResponse{EmailVerified: verified}, nil
}

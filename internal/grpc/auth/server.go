package grpcauth

import (
	"context"
	"errors"
	"time"

	auth "github.com/GosMachine/ServiceAuth/internal/services"
	"github.com/GosMachine/ServiceAuth/internal/storage"
	"github.com/GosMachine/ServiceAuth/internal/utils"
	authv1 "github.com/GosMachine/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Auth interface {
	Login(email, password, ip, rememberMe string) (token string, tokenTTL time.Duration, err error)
	Logout(token string) error
	OAuth(email, ip string) (token string, tokenTTL time.Duration, err error)
	CreateToken(email, remember string) (string, time.Duration)
	GetUserEmail(token string) string
	EmailVerified(email string) (verified bool, err error)
	EmailVerify(email string) error
	ChangeEmail(email, newEmail, oldToken string) (token string, tokenTTL time.Duration, err error)
	Register(email, password, ip, rememberMe string) (token string, tokenTTL time.Duration, err error)
	ChangePass(email, password, ip, oldToken string) (token string, tokenTTL time.Duration, err error)
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
	token, tokenTTL, err := s.auth.Login(req.Email, req.Password, req.IP, req.RememberMe)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &authv1.LoginResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *authv1.LogoutRequest) (*emptypb.Empty, error) {
	err := s.auth.Logout(req.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to logout")
	}
	return &emptypb.Empty{}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if !utils.ValidateAuthData(req.Email, req.Password) {
		return nil, status.Error(codes.InvalidArgument, "invalid email or password")
	}
	token, tokenTTL, err := s.auth.Register(req.Email, req.Password, req.IP, req.RememberMe)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		return nil, status.Error(codes.Internal, "failed to register user")
	}
	return &authv1.RegisterResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
}

func (s *serverAPI) OAuth(ctx context.Context, req *authv1.OAuthRequest) (*authv1.OAuthResponse, error) {
	token, tokenTTL, err := s.auth.OAuth(req.Email, req.IP)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to OAuth")
	}
	return &authv1.OAuthResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
}

func (s *serverAPI) ChangePass(ctx context.Context, req *authv1.ChangePassRequest) (*authv1.ChangePassResponse, error) {
	if !utils.ValidateAuthData(req.Email, req.Password) {
		return nil, status.Error(codes.InvalidArgument, "invalid email or password")
	}
	token, tokenTTL, err := s.auth.ChangePass(req.Email, req.Password, req.IP, req.OldToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to change password")
	}
	return &authv1.ChangePassResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
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

func (s *serverAPI) ChangeEmail(ctx context.Context, req *authv1.ChangeEmailRequest) (*authv1.ChangeEmailResponse, error) {
	token, tokenTTL, err := s.auth.ChangeEmail(req.Email, req.NewEmail, req.OldToken)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &authv1.ChangeEmailResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
}

func (s *serverAPI) EmailVerify(ctx context.Context, req *authv1.EmailVerifyRequest) (*emptypb.Empty, error) {
	err := s.auth.EmailVerify(req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "email verify failed")
	}
	return &emptypb.Empty{}, nil
}

func (s *serverAPI) CreateToken(ctx context.Context, req *authv1.CreateTokenRequest) (*authv1.CreateTokenResponse, error) {
	token, tokenTTL := s.auth.CreateToken(req.Email, req.Remember)
	return &authv1.CreateTokenResponse{Token: token, TokenTTL: int64(tokenTTL.Minutes())}, nil
}

func (s *serverAPI) GetUserEmail(ctx context.Context, req *authv1.GetUserEmailRequest) (*authv1.GetUserEmailResponse, error) {
	email := s.auth.GetUserEmail(req.Token)
	return &authv1.GetUserEmailResponse{Email: email}, nil
}

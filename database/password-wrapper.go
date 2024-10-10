package database

import (
	"context"
	"github.com/1f349/lavender/database/types"
	"github.com/1f349/lavender/password"
	"github.com/google/uuid"
	"time"
)

type AddLocalUserParams struct {
	Password       string `json:"password"`
	Email          string `json:"email"`
	EmailVerified  bool   `json:"email_verified"`
	Name           string `json:"name"`
	Username       string `json:"username"`
	ChangePassword bool   `json:"change_password"`
}

func (q *Queries) AddLocalUser(ctx context.Context, arg AddLocalUserParams) (string, error) {
	pwHash, err := password.HashPassword(arg.Password)
	if err != nil {
		return "", err
	}
	n := time.Now()
	a := addUserParams{
		Subject:        uuid.NewString(),
		Password:       pwHash,
		Email:          arg.Email,
		EmailVerified:  arg.EmailVerified,
		UpdatedAt:      n,
		Registered:     n,
		Active:         true,
		Name:           arg.Name,
		Login:          arg.Username,
		ChangePassword: arg.ChangePassword,
		AuthType:       types.AuthTypeLocal,
		AuthNamespace:  "",
		AuthUser:       arg.Username,
	}
	return a.Subject, q.addUser(ctx, a)
}

type AddOAuthUserParams struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Username      string `json:"username"`
	AuthNamespace string `json:"auth_namespace"`
	AuthUser      string `json:"auth_user"`
}

func (q *Queries) AddOAuthUser(ctx context.Context, arg AddOAuthUserParams) (string, error) {
	n := time.Now()
	a := addUserParams{
		Subject:        uuid.NewString(),
		Email:          arg.Email,
		EmailVerified:  arg.EmailVerified,
		UpdatedAt:      n,
		Registered:     n,
		Active:         true,
		Name:           arg.Name,
		Login:          arg.Username,
		ChangePassword: false,
		AuthType:       types.AuthTypeOauth2,
		AuthNamespace:  arg.AuthNamespace,
		AuthUser:       arg.AuthUser,
	}
	return a.Subject, q.addUser(ctx, a)
}

type CheckLoginResult struct {
	Subject       string `json:"subject"`
	NeedFactor    bool   `json:"need_factor"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func (q *Queries) CheckLogin(ctx context.Context, un, pw string) (CheckLoginResult, error) {
	login, err := q.checkLogin(ctx, un)
	if err != nil {
		return CheckLoginResult{}, err
	}
	err = password.CheckPasswordHash(login.Password, pw)
	if err != nil {
		return CheckLoginResult{}, err
	}
	return CheckLoginResult{
		Subject:       login.Subject,
		NeedFactor:    login.NeedFactor,
		Email:         login.Email,
		EmailVerified: login.EmailVerified,
	}, nil
}

func (q *Queries) ChangePassword(ctx context.Context, subject, newPw string) error {
	userPassword, err := q.getUserPassword(ctx, subject)
	if err != nil {
		return err
	}
	newPwHash, err := password.HashPassword(newPw)
	if err != nil {
		return err
	}
	return q.changeUserPassword(ctx, changeUserPasswordParams{
		Password:   newPwHash,
		UpdatedAt:  time.Now(),
		Subject:    subject,
		Password_2: userPassword,
	})
}

package database

import (
	"context"
	"github.com/1f349/lavender/password"
	"github.com/google/uuid"
	"time"
)

type AddUserParams struct {
	Name          string    `json:"name"`
	Subject       string    `json:"subject"`
	Password      string    `json:"password"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	UpdatedAt     time.Time `json:"updated_at"`
	Active        bool      `json:"active"`
}

func (q *Queries) AddUser(ctx context.Context, arg AddUserParams) (string, error) {
	pwHash, err := password.HashPassword(arg.Password)
	if err != nil {
		return "", err
	}
	n := time.Now()
	a := addUserParams{
		Subject:       uuid.NewString(),
		Password:      pwHash,
		Email:         arg.Email,
		EmailVerified: arg.EmailVerified,
		UpdatedAt:     n,
		Registered:    n,
		Active:        true,
	}
	return a.Subject, q.addUser(ctx, a)
}

type CheckLoginResult struct {
	Subject       string `json:"subject"`
	HasOtp        bool   `json:"has_otp"`
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
		HasOtp:        login.HasOtp,
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

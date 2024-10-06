// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: users.sql

package database

import (
	"context"
	"time"

	"github.com/1f349/lavender/database/types"
	"github.com/1f349/lavender/password"
)

const findUserByAuth = `-- name: FindUserByAuth :one
SELECT subject
FROM users
WHERE auth_type = ?
  AND auth_namespace = ?
  AND auth_user = ?
`

type FindUserByAuthParams struct {
	AuthType      types.AuthType `json:"auth_type"`
	AuthNamespace string         `json:"auth_namespace"`
	AuthUser      string         `json:"auth_user"`
}

func (q *Queries) FindUserByAuth(ctx context.Context, arg FindUserByAuthParams) (string, error) {
	row := q.db.QueryRowContext(ctx, findUserByAuth, arg.AuthType, arg.AuthNamespace, arg.AuthUser)
	var subject string
	err := row.Scan(&subject)
	return subject, err
}

const flagUserAsDeleted = `-- name: FlagUserAsDeleted :exec
UPDATE users
SET active= false,
    to_delete = true
WHERE subject = ?
`

func (q *Queries) FlagUserAsDeleted(ctx context.Context, subject string) error {
	_, err := q.db.ExecContext(ctx, flagUserAsDeleted, subject)
	return err
}

const getUser = `-- name: GetUser :one
SELECT id, subject, password, change_password, email, email_verified, updated_at, registered, active, name, picture, website, pronouns, birthdate, zone, locale, login, profile_url, auth_type, auth_namespace, auth_user, access_token, refresh_token, token_expiry, otp_secret, otp_digits, to_delete
FROM users
WHERE subject = ?
LIMIT 1
`

func (q *Queries) GetUser(ctx context.Context, subject string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, subject)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Subject,
		&i.Password,
		&i.ChangePassword,
		&i.Email,
		&i.EmailVerified,
		&i.UpdatedAt,
		&i.Registered,
		&i.Active,
		&i.Name,
		&i.Picture,
		&i.Website,
		&i.Pronouns,
		&i.Birthdate,
		&i.Zone,
		&i.Locale,
		&i.Login,
		&i.ProfileUrl,
		&i.AuthType,
		&i.AuthNamespace,
		&i.AuthUser,
		&i.AccessToken,
		&i.RefreshToken,
		&i.TokenExpiry,
		&i.OtpSecret,
		&i.OtpDigits,
		&i.ToDelete,
	)
	return i, err
}

const getUserRoles = `-- name: GetUserRoles :many
SELECT r.role
FROM users_roles
         INNER JOIN roles r on r.id = users_roles.role_id
         INNER JOIN users u on u.id = users_roles.user_id
WHERE u.subject = ?
`

func (q *Queries) GetUserRoles(ctx context.Context, subject string) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, getUserRoles, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		items = append(items, role)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const hasUser = `-- name: HasUser :one
SELECT count(subject) > 0 AS hasUser
FROM users
`

func (q *Queries) HasUser(ctx context.Context) (bool, error) {
	row := q.db.QueryRowContext(ctx, hasUser)
	var hasuser bool
	err := row.Scan(&hasuser)
	return hasuser, err
}

const userHasRole = `-- name: UserHasRole :exec
SELECT 1
FROM roles
         INNER JOIN users_roles on users_roles.user_id = roles.id
         INNER JOIN users u on u.id = users_roles.user_id = u.id
WHERE roles.role = ?
  AND u.subject = ?
`

type UserHasRoleParams struct {
	Role    string `json:"role"`
	Subject string `json:"subject"`
}

func (q *Queries) UserHasRole(ctx context.Context, arg UserHasRoleParams) error {
	_, err := q.db.ExecContext(ctx, userHasRole, arg.Role, arg.Subject)
	return err
}

const addUser = `-- name: addUser :exec
INSERT INTO users (subject, password, email, email_verified, updated_at, registered, active, name, login, change_password, auth_type, auth_namespace, auth_user)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

type addUserParams struct {
	Subject        string              `json:"subject"`
	Password       password.HashString `json:"password"`
	Email          string              `json:"email"`
	EmailVerified  bool                `json:"email_verified"`
	UpdatedAt      time.Time           `json:"updated_at"`
	Registered     time.Time           `json:"registered"`
	Active         bool                `json:"active"`
	Name           string              `json:"name"`
	Login          string              `json:"login"`
	ChangePassword bool                `json:"change_password"`
	AuthType       types.AuthType      `json:"auth_type"`
	AuthNamespace  string              `json:"auth_namespace"`
	AuthUser       string              `json:"auth_user"`
}

func (q *Queries) addUser(ctx context.Context, arg addUserParams) error {
	_, err := q.db.ExecContext(ctx, addUser,
		arg.Subject,
		arg.Password,
		arg.Email,
		arg.EmailVerified,
		arg.UpdatedAt,
		arg.Registered,
		arg.Active,
		arg.Name,
		arg.Login,
		arg.ChangePassword,
		arg.AuthType,
		arg.AuthNamespace,
		arg.AuthUser,
	)
	return err
}

const changeUserPassword = `-- name: changeUserPassword :exec
UPDATE users
SET password  = ?,
    updated_at=?
WHERE subject = ?
  AND password = ?
`

type changeUserPasswordParams struct {
	Password   password.HashString `json:"password"`
	UpdatedAt  time.Time           `json:"updated_at"`
	Subject    string              `json:"subject"`
	Password_2 password.HashString `json:"password_2"`
}

func (q *Queries) changeUserPassword(ctx context.Context, arg changeUserPasswordParams) error {
	_, err := q.db.ExecContext(ctx, changeUserPassword,
		arg.Password,
		arg.UpdatedAt,
		arg.Subject,
		arg.Password_2,
	)
	return err
}

const checkLogin = `-- name: checkLogin :one
SELECT subject, password, CAST(otp_secret != '' AS BOOLEAN) AS has_otp, email, email_verified
FROM users
WHERE users.subject = ?
LIMIT 1
`

type checkLoginRow struct {
	Subject       string              `json:"subject"`
	Password      password.HashString `json:"password"`
	HasOtp        bool                `json:"has_otp"`
	Email         string              `json:"email"`
	EmailVerified bool                `json:"email_verified"`
}

func (q *Queries) checkLogin(ctx context.Context, subject string) (checkLoginRow, error) {
	row := q.db.QueryRowContext(ctx, checkLogin, subject)
	var i checkLoginRow
	err := row.Scan(
		&i.Subject,
		&i.Password,
		&i.HasOtp,
		&i.Email,
		&i.EmailVerified,
	)
	return i, err
}

const getUserPassword = `-- name: getUserPassword :one
SELECT password
FROM users
WHERE subject = ?
`

func (q *Queries) getUserPassword(ctx context.Context, subject string) (password.HashString, error) {
	row := q.db.QueryRowContext(ctx, getUserPassword, subject)
	var password password.HashString
	err := row.Scan(&password)
	return password, err
}

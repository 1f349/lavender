// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: otp.sql

package database

import (
	"context"
)

const deleteOtp = `-- name: DeleteOtp :exec
UPDATE users
SET otp_secret='',
    otp_digits=0
WHERE subject = ?
`

func (q *Queries) DeleteOtp(ctx context.Context, subject string) error {
	_, err := q.db.ExecContext(ctx, deleteOtp, subject)
	return err
}

const getOtp = `-- name: GetOtp :one
SELECT otp_secret, otp_digits
FROM users
WHERE subject = ?
`

type GetOtpRow struct {
	OtpSecret string `json:"otp_secret"`
	OtpDigits int64  `json:"otp_digits"`
}

func (q *Queries) GetOtp(ctx context.Context, subject string) (GetOtpRow, error) {
	row := q.db.QueryRowContext(ctx, getOtp, subject)
	var i GetOtpRow
	err := row.Scan(&i.OtpSecret, &i.OtpDigits)
	return i, err
}

const getUserEmail = `-- name: GetUserEmail :one
SELECT email
FROM users
WHERE subject = ?
`

func (q *Queries) GetUserEmail(ctx context.Context, subject string) (string, error) {
	row := q.db.QueryRowContext(ctx, getUserEmail, subject)
	var email string
	err := row.Scan(&email)
	return email, err
}

const hasOtp = `-- name: HasOtp :one
SELECT CAST(1 AS BOOLEAN) AS hasOtp
FROM users
WHERE subject = ?
  AND otp_secret != ''
`

func (q *Queries) HasOtp(ctx context.Context, subject string) (bool, error) {
	row := q.db.QueryRowContext(ctx, hasOtp, subject)
	var hasotp bool
	err := row.Scan(&hasotp)
	return hasotp, err
}

const setOtp = `-- name: SetOtp :exec
UPDATE users
SET otp_secret = ?,
    otp_digits=?
WHERE subject = ?
`

type SetOtpParams struct {
	OtpSecret string `json:"otp_secret"`
	OtpDigits int64  `json:"otp_digits"`
	Subject   string `json:"subject"`
}

func (q *Queries) SetOtp(ctx context.Context, arg SetOtpParams) error {
	_, err := q.db.ExecContext(ctx, setOtp, arg.OtpSecret, arg.OtpDigits, arg.Subject)
	return err
}
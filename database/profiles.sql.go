// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: profiles.sql

package database

import (
	"context"
	"time"

	"github.com/1f349/lavender/database/types"
	"github.com/hardfinhq/go-date"
)

const getProfile = `-- name: GetProfile :one
SELECT subject,
       name,
       picture,
       website,
       pronouns,
       birthdate,
       zone,
       locale
FROM users
WHERE subject = ?
`

type GetProfileRow struct {
	Subject   string            `json:"subject"`
	Name      string            `json:"name"`
	Picture   string            `json:"picture"`
	Website   string            `json:"website"`
	Pronouns  types.UserPronoun `json:"pronouns"`
	Birthdate date.NullDate     `json:"birthdate"`
	Zone      string            `json:"zone"`
	Locale    types.UserLocale  `json:"locale"`
}

func (q *Queries) GetProfile(ctx context.Context, subject string) (GetProfileRow, error) {
	row := q.db.QueryRowContext(ctx, getProfile, subject)
	var i GetProfileRow
	err := row.Scan(
		&i.Subject,
		&i.Name,
		&i.Picture,
		&i.Website,
		&i.Pronouns,
		&i.Birthdate,
		&i.Zone,
		&i.Locale,
	)
	return i, err
}

const modifyProfile = `-- name: ModifyProfile :exec
UPDATE users
SET name       = ?,
    picture    = ?,
    website    = ?,
    pronouns   = ?,
    birthdate  = ?,
    zone       = ?,
    locale     = ?,
    updated_at = ?
WHERE subject = ?
`

type ModifyProfileParams struct {
	Name      string            `json:"name"`
	Picture   string            `json:"picture"`
	Website   string            `json:"website"`
	Pronouns  types.UserPronoun `json:"pronouns"`
	Birthdate date.NullDate     `json:"birthdate"`
	Zone      string            `json:"zone"`
	Locale    types.UserLocale  `json:"locale"`
	UpdatedAt time.Time         `json:"updated_at"`
	Subject   string            `json:"subject"`
}

func (q *Queries) ModifyProfile(ctx context.Context, arg ModifyProfileParams) error {
	_, err := q.db.ExecContext(ctx, modifyProfile,
		arg.Name,
		arg.Picture,
		arg.Website,
		arg.Pronouns,
		arg.Birthdate,
		arg.Zone,
		arg.Locale,
		arg.UpdatedAt,
		arg.Subject,
	)
	return err
}
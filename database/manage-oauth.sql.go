// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: manage-oauth.sql

package database

import (
	"context"
)

const getAppList = `-- name: GetAppList :many
SELECT subject,
       name,
       domain,
       owner_subject,
       perms,
       public,
       sso,
       active
FROM client_store
WHERE owner_subject = ?
   OR ? = 1
LIMIT 25 OFFSET ?
`

type GetAppListParams struct {
	OwnerSubject string      `json:"owner_subject"`
	Column2      interface{} `json:"column_2"`
	Offset       int64       `json:"offset"`
}

type GetAppListRow struct {
	Subject      string `json:"subject"`
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	OwnerSubject string `json:"owner_subject"`
	Perms        string `json:"perms"`
	Public       bool   `json:"public"`
	Sso          bool   `json:"sso"`
	Active       bool   `json:"active"`
}

func (q *Queries) GetAppList(ctx context.Context, arg GetAppListParams) ([]GetAppListRow, error) {
	rows, err := q.db.QueryContext(ctx, getAppList, arg.OwnerSubject, arg.Column2, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAppListRow
	for rows.Next() {
		var i GetAppListRow
		if err := rows.Scan(
			&i.Subject,
			&i.Name,
			&i.Domain,
			&i.OwnerSubject,
			&i.Perms,
			&i.Public,
			&i.Sso,
			&i.Active,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getClientInfo = `-- name: GetClientInfo :one
SELECT subject, name, secret, domain, owner_subject, perms, public, sso, active
FROM client_store
WHERE subject = ?
LIMIT 1
`

func (q *Queries) GetClientInfo(ctx context.Context, subject string) (ClientStore, error) {
	row := q.db.QueryRowContext(ctx, getClientInfo, subject)
	var i ClientStore
	err := row.Scan(
		&i.Subject,
		&i.Name,
		&i.Secret,
		&i.Domain,
		&i.OwnerSubject,
		&i.Perms,
		&i.Public,
		&i.Sso,
		&i.Active,
	)
	return i, err
}

const insertClientApp = `-- name: InsertClientApp :exec
INSERT INTO client_store (subject, name, secret, domain, perms, public, sso, active, owner_subject)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

type InsertClientAppParams struct {
	Subject      string `json:"subject"`
	Name         string `json:"name"`
	Secret       string `json:"secret"`
	Domain       string `json:"domain"`
	Perms        string `json:"perms"`
	Public       bool   `json:"public"`
	Sso          bool   `json:"sso"`
	Active       bool   `json:"active"`
	OwnerSubject string `json:"owner_subject"`
}

func (q *Queries) InsertClientApp(ctx context.Context, arg InsertClientAppParams) error {
	_, err := q.db.ExecContext(ctx, insertClientApp,
		arg.Subject,
		arg.Name,
		arg.Secret,
		arg.Domain,
		arg.Perms,
		arg.Public,
		arg.Sso,
		arg.Active,
		arg.OwnerSubject,
	)
	return err
}

const resetClientAppSecret = `-- name: ResetClientAppSecret :exec
UPDATE client_store
SET secret = ?
WHERE subject = ?
  AND owner_subject = ?
`

type ResetClientAppSecretParams struct {
	Secret       string `json:"secret"`
	Subject      string `json:"subject"`
	OwnerSubject string `json:"owner_subject"`
}

func (q *Queries) ResetClientAppSecret(ctx context.Context, arg ResetClientAppSecretParams) error {
	_, err := q.db.ExecContext(ctx, resetClientAppSecret, arg.Secret, arg.Subject, arg.OwnerSubject)
	return err
}

const updateClientApp = `-- name: UpdateClientApp :exec
UPDATE client_store
SET name   = ?,
    domain = ?,
    perms  = CASE WHEN CAST(? AS BOOLEAN) = true THEN ? ELSE perms END,
    public = ?,
    sso    = ?,
    active = ?
WHERE subject = ?
  AND owner_subject = ?
`

type UpdateClientAppParams struct {
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Column3      bool   `json:"column_3"`
	Perms        string `json:"perms"`
	Public       bool   `json:"public"`
	Sso          bool   `json:"sso"`
	Active       bool   `json:"active"`
	Subject      string `json:"subject"`
	OwnerSubject string `json:"owner_subject"`
}

func (q *Queries) UpdateClientApp(ctx context.Context, arg UpdateClientAppParams) error {
	_, err := q.db.ExecContext(ctx, updateClientApp,
		arg.Name,
		arg.Domain,
		arg.Column3,
		arg.Perms,
		arg.Public,
		arg.Sso,
		arg.Active,
		arg.Subject,
		arg.OwnerSubject,
	)
	return err
}

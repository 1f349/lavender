// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package database

import (
	"database/sql"
	"time"
)

type ClientStore struct {
	Subject string `json:"subject"`
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Domain  string `json:"domain"`
	Owner   string `json:"owner"`
	Perms   string `json:"perms"`
	Public  bool   `json:"public"`
	Sso     bool   `json:"sso"`
	Active  bool   `json:"active"`
}

type User struct {
	Subject       string         `json:"subject"`
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Roles         string         `json:"roles"`
	Userinfo      string         `json:"userinfo"`
	AccessToken   sql.NullString `json:"access_token"`
	RefreshToken  sql.NullString `json:"refresh_token"`
	Expiry        sql.NullTime   `json:"expiry"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Active        bool           `json:"active"`
}
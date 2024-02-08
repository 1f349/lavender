package database

import (
	"database/sql"
	"fmt"
	"github.com/1f349/lavender/password"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/google/uuid"
	"time"
)

func updatedAt() string {
	return time.Now().UTC().Format(time.DateTime)
}

type Tx struct{ tx *sql.Tx }

func (t *Tx) Commit() error {
	return t.tx.Commit()
}

func (t *Tx) Rollback() {
	_ = t.tx.Rollback()
}

func (t *Tx) HasUser() error {
	var exists bool
	row := t.tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users)`)
	err := row.Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	return nil
}

func (t *Tx) InsertUser(subject, email string, verifyEmail bool, roles string, active bool) error {
	_, err := t.tx.Exec(`INSERT INTO users (subject, email, email_verified, roles, updated_at, active) VALUES (?, ?, ?, ?, ?, ?)`, subject, email, verifyEmail, roles, updatedAt(), active)
	return err
}

func (t *Tx) GetUserRoles(sub string) (string, error) {
	var r string
	row := t.tx.QueryRow(`SELECT roles FROM users WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&r)
	return r, err
}

func (t *Tx) GetUser(sub string) (*User, error) {
	var u User
	row := t.tx.QueryRow(`SELECT email, email_verified, roles, updated_at, active FROM users WHERE subject = ?`, sub)
	err := row.Scan(&u.Email, &u.EmailVerified, &u.Roles, &u.UpdatedAt, &u.Active)
	u.Sub = sub
	return &u, err
}

func (t *Tx) GetUserEmail(sub string) (string, error) {
	var email string
	row := t.tx.QueryRow(`SELECT email FROM users WHERE subject = ?`, sub)
	err := row.Scan(&email)
	return email, err
}

func (t *Tx) GetClientInfo(sub string) (oauth2.ClientInfo, error) {
	var u ClientInfoDbOutput
	row := t.tx.QueryRow(`SELECT secret, name, domain, public, sso, active FROM client_store WHERE subject = ? LIMIT 1`, sub)
	err := row.Scan(&u.Secret, &u.Name, &u.Domain, &u.Public, &u.SSO, &u.Active)
	u.Owner = sub
	if !u.Active {
		return nil, fmt.Errorf("client is not active")
	}
	return &u, err
}

func (t *Tx) GetAppList(owner string, admin bool, offset int) ([]ClientInfoDbOutput, error) {
	var u []ClientInfoDbOutput
	row, err := t.tx.Query(`SELECT subject, name, domain, owner, public, sso, active FROM client_store WHERE owner = ? OR ? = 1 LIMIT 25 OFFSET ?`, owner, admin, offset)
	if err != nil {
		return nil, err
	}
	defer row.Close()
	for row.Next() {
		var a ClientInfoDbOutput
		err := row.Scan(&a.Sub, &a.Name, &a.Domain, &a.Owner, &a.Public, &a.SSO, &a.Active)
		if err != nil {
			return nil, err
		}
		u = append(u, a)
	}
	return u, row.Err()
}

func (t *Tx) InsertClientApp(name, domain string, public, sso, active bool, owner string) error {
	u := uuid.New()
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(`INSERT INTO client_store (subject, name, secret, domain, owner, public, sso, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, u.String(), name, secret, domain, owner, public, sso, active)
	return err
}

func (t *Tx) UpdateClientApp(subject uuid.UUID, owner string, name, domain string, public, sso, active bool) error {
	_, err := t.tx.Exec(`UPDATE client_store SET name = ?, domain = ?, public = ?, sso = ?, active = ? WHERE subject = ? AND owner = ?`, name, domain, public, sso, active, subject.String(), owner)
	return err
}

func (t *Tx) ResetClientAppSecret(subject uuid.UUID, owner string) (string, error) {
	secret, err := password.GenerateApiSecret(70)
	if err != nil {
		return "", err
	}
	_, err = t.tx.Exec(`UPDATE client_store SET secret = ? WHERE subject = ? AND owner = ?`, secret, subject.String(), owner)
	return secret, err
}

func (t *Tx) GetUserList(offset int) ([]User, error) {
	var u []User
	row, err := t.tx.Query(`SELECT subject, email, email_verified, roles, updated_at, active FROM users LIMIT 25 OFFSET ?`, offset)
	if err != nil {
		return nil, err
	}
	for row.Next() {
		var a User
		err := row.Scan(&a.Sub, &a.Email, &a.EmailVerified, &a.Roles, &a.UpdatedAt, &a.Active)
		if err != nil {
			return nil, err
		}
		u = append(u, a)
	}
	return u, row.Err()
}

func (t *Tx) UpdateUser(subject, roles string, active bool) error {
	_, err := t.tx.Exec(`UPDATE users SET active = ?, roles = ? WHERE subject = ?`, active, roles, subject)
	return err
}

func (t *Tx) UserEmailExists(email string) (exists bool, err error) {
	row := t.tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? and email_verified = 1)`, email)
	err = row.Scan(&exists)
	return
}

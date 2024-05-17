-- name: HasUser :one
SELECT count(subject) > 0 AS hasUser
FROM users;

-- name: AddUser :exec
INSERT INTO users (subject, email, email_verified, roles, userinfo, updated_at, active)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: UpdateUserInfo :exec
UPDATE users
SET email          = ?,
    email_verified = ?,
    userinfo       = ?
WHERE subject = ?;

-- name: GetUserRoles :one
SELECT roles
FROM users
WHERE subject = ?;

-- name: GetUser :one
SELECT *
FROM users
WHERE subject = ?
LIMIT 1;

-- name: UpdateUserToken :exec
UPDATE users
SET access_token  = ?,
    refresh_token = ?,
    expiry        = ?
WHERE subject = ?;

-- name: GetUserToken :one
SELECT access_token, refresh_token, expiry
FROM users
WHERE subject = ?
LIMIT 1;

-- name: GetUserEmail :one
SELECT email
FROM users
WHERE subject = ?;

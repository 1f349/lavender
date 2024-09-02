-- name: HasUser :one
SELECT count(subject) > 0 AS hasUser
FROM users;

-- name: addUser :exec
INSERT INTO users (subject, password, email, email_verified, updated_at, registered, active)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: checkLogin :one
SELECT subject, password, EXISTS(SELECT 1 FROM otp WHERE otp.subject = users.subject) == 1 AS has_otp, email, email_verified
FROM users
WHERE users.subject = ?
LIMIT 1;

-- name: GetUser :one
SELECT *
FROM users
WHERE subject = ?
LIMIT 1;

-- name: GetUserRoles :many
SELECT r.role
FROM users_roles
         INNER JOIN roles r on r.id = users_roles.role_id
         INNER JOIN users u on u.id = users_roles.user_id
WHERE u.subject = ?;

-- name: UserHasRole :one
SELECT 1
FROM roles
         INNER JOIN users_roles on users_roles.user_id = roles.id
         INNER JOIN users u on u.id = users_roles.user_id = u.id
WHERE roles.role = ?
  AND u.subject = ?;

-- name: getUserPassword :one
SELECT password
FROM users
WHERE subject = ?;

-- name: changeUserPassword :exec
UPDATE users
SET password  = ?,
    updated_at=?
WHERE subject = ?
  AND password = ?;

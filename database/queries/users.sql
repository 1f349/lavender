-- name: HasUser :one
SELECT count(subject) > 0 AS hasUser
FROM users;

-- name: addUser :exec
INSERT INTO users (subject, password, email, email_verified, updated_at, registered, active, name, login, change_password, auth_type, auth_namespace, auth_user)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: checkLogin :one
SELECT subject, password, CAST(otp_secret != '' AS BOOLEAN) AS has_otp, email, email_verified
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

-- name: UserHasRole :exec
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

-- name: FlagUserAsDeleted :exec
UPDATE users
SET active= false,
    to_delete = true
WHERE subject = ?;

-- name: FindUserByAuth :one
SELECT subject
FROM users
WHERE auth_type = ?
  AND auth_namespace = ?
  AND auth_user = ?;

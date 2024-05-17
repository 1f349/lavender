-- name: GetUserList :many
SELECT subject,
       email,
       email_verified,
       roles,
       updated_at,
       active
FROM users
LIMIT 25 OFFSET ?;

-- name: UpdateUser :exec
UPDATE users
SET active = ?,
    roles=?
WHERE subject = ?;

-- name: UserEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND email_verified = 1) == 1 AS email_exists;

-- name: GetUserList :many
SELECT users.subject,
       name,
       picture,
       website,
       email,
       email_verified,
       users.updated_at as user_updated_at,
       p.updated_at     as profile_updated_at,
       active
FROM users
         INNER JOIN main.profiles p on users.subject = p.subject
LIMIT 50 OFFSET ?;

-- name: GetUsersRoles :many
SELECT r.role, u.id
FROM users_roles
         INNER JOIN roles r on r.id = users_roles.role_id
         INNER JOIN users u on u.id = users_roles.user_id
WHERE u.id in sqlc.slice(user_ids);

-- name: ChangeUserActive :exec
UPDATE users
SET active = cast(? as boolean)
WHERE subject = ?;

-- name: UserEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND email_verified = 1) == 1 AS email_exists;

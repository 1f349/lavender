-- name: GetUserList :many
SELECT users.subject,
       name,
       picture,
       website,
       email,
       email_verified,
       updated_at,
       active
FROM users
--INNER JOIN main.profiles p on users.subject = p.subject
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

-- name: VerifyUserEmail :exec
UPDATE users
SET email_verified=1
WHERE subject = ?;

-- name: UserEmailExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND email_verified = 1) == 1 AS email_exists;

-- name: ModifyUserEmail :exec
UPDATE users
SET email         = ?,
    email_verified=?
WHERE subject = ?;

-- name: ModifyUserAuth :exec
UPDATE users
SET auth_type     = ?,
    auth_namespace=?,
    auth_user     = ?
WHERE subject = ?;

-- name: ModifyUserRemoteLogin :exec
UPDATE users
SET login       = ?,
    profile_url = ?
WHERE subject = ?;

-- name: UpdateUserToken :exec
UPDATE users
SET access_token = ?,
    refresh_token=?,
    token_expiry = ?
WHERE subject = ?;

-- name: GetUserToken :one
SELECT access_token, refresh_token, token_expiry
FROM users
WHERE subject = ?;

-- name: RemoveUserRoles :exec
DELETE
FROM users_roles
WHERE user_id IN (SELECT id
                  FROM users
                  WHERE subject = ?);

-- name: AddUserRole :exec
INSERT INTO users_roles(role_id, user_id)
SELECT ?, users.id
FROM users
WHERE subject = ?;

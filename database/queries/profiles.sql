-- name: GetProfile :one
SELECT subject,
       name,
       picture,
       website,
       pronouns,
       birthdate,
       zone,
       locale
FROM users
WHERE subject = ?;

-- name: ModifyProfile :exec
UPDATE users
SET name       = ?,
    picture    = ?,
    website    = ?,
    pronouns   = ?,
    birthdate  = ?,
    zone       = ?,
    locale     = ?,
    updated_at = ?
WHERE subject = ?;

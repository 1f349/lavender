-- name: GetProfile :one
SELECT profiles.*
FROM profiles
WHERE subject = ?;

-- name: ModifyProfile :exec
UPDATE profiles
SET name       = ?,
    picture    = ?,
    website    = ?,
    pronouns   = ?,
    birthdate  = ?,
    zone       = ?,
    locale     = ?,
    updated_at = ?
WHERE subject = ?;

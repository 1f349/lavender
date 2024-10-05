-- name: SetOtp :exec
UPDATE users
SET otp_secret = ?,
    otp_digits=?
WHERE subject = ?;

-- name: DeleteOtp :exec
UPDATE users
SET otp_secret='',
    otp_digits=0
WHERE subject = ?;

-- name: GetOtp :one
SELECT otp_secret, otp_digits
FROM users
WHERE subject = ?;

-- name: HasOtp :one
SELECT CAST(1 AS BOOLEAN) AS hasOtp
FROM users
WHERE subject = ?
  AND otp_secret != '';

-- name: GetUserEmail :one
SELECT email
FROM users
WHERE subject = ?;

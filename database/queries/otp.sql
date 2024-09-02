-- name: SetOtp :exec
INSERT OR
REPLACE
INTO otp (subject, secret, digits)
VALUES (?, ?, ?);

-- name: DeleteOtp :exec
DELETE
FROM otp
WHERE otp.subject = ?;

-- name: GetOtp :one
SELECT secret, digits
FROM otp
WHERE subject = ?;

-- name: HasOtp :one
SELECT EXISTS(SELECT 1 FROM otp WHERE subject = ?) == 1 as hasOtp;

-- name: GetUserEmail :one
SELECT email
FROM users
WHERE subject = ?;

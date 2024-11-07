-- name: AddRole :execlastid
INSERT OR IGNORE INTO roles(role)
VALUES (?);

-- name: RemoveRole :exec
DELETE
FROM roles
WHERE role = ?;

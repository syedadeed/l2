-- name: AddUser :exec
INSERT INTO users(id, first_name, last_name, username) VALUES($1, $2, $3, $4);

-- name: AddCredential :exec
INSERT INTO passkey_credentials(id, user_id, credential) VALUES($1, $2, $3);

-- name: VerifyCredentialOwner :one
SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE id = sqlc.arg(cred_id) AND user_id = sqlc.arg(user_id));

-- name: GetCredentialsByUser :many
SELECT credential FROM passkey_credentials WHERE user_id = $1;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: UpdateCredential :exec
UPDATE passkey_credentials SET credential = $1 WHERE id = $2;

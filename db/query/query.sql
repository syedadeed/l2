-- name: AddUser :exec
INSERT INTO users(id, first_name, last_name, username) VALUES($1, $2, $3, $4);

-- name: AddCredential :exec
INSERT INTO passkey_credentials(id, user_id, credential) VALUES($1, $2, $3);

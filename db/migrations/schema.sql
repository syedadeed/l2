CREATE TABLE users (
    id         UUID        PRIMARY KEY,
    first_name VARCHAR(10) NOT NULL,
    last_name  VARCHAR(10) NOT NULL,
    username   VARCHAR(22) NOT NULL UNIQUE CHECK (username ~ '^[A-Za-z0-9_-]+$')
);

CREATE TABLE passkey_credentials (
    id            BYTEA       PRIMARY KEY,
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential    JSONB       NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id            UUID        PRIMARY KEY,
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL
);

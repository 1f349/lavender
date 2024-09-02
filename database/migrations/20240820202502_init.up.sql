CREATE TABLE users
(
    id             INTEGER  NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    subject        TEXT     NOT NULL UNIQUE,
    password       TEXT     NOT NULL,

    email          TEXT     NOT NULL,
    email_verified BOOLEAN  NOT NULL DEFAULT 0,

    updated_at     DATETIME NOT NULL,
    registered     DATETIME NOT NULL,
    active         BOOLEAN  NOT NULL DEFAULT 1
);

CREATE INDEX users_subject ON users (subject);

CREATE TABLE profiles
(
    subject    TEXT     NOT NULL UNIQUE PRIMARY KEY,
    name       TEXT     NOT NULL,
    picture    TEXT     NOT NULL DEFAULT '',
    website    TEXT     NOT NULL DEFAULT '',
    pronouns   TEXT     NOT NULL DEFAULT 'they/them',
    birthdate  DATE     NULL,
    zone       TEXT     NOT NULL DEFAULT 'UTC',
    locale     TEXT     NOT NULL DEFAULT 'en-US',
    updated_at DATETIME NOT NULL
);

CREATE TABLE roles
(
    id   INTEGER NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    role TEXT    NOT NULL UNIQUE
);

CREATE TABLE users_roles
(
    role_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,

    FOREIGN KEY (role_id) REFERENCES roles (id),
    FOREIGN KEY (user_id) REFERENCES users (id),

    CONSTRAINT user_role UNIQUE (role_id, user_id)
);

CREATE TABLE otp
(
    subject INTEGER NOT NULL UNIQUE PRIMARY KEY,
    secret  TEXT    NOT NULL,
    digits  INTEGER NOT NULL,

    FOREIGN KEY (subject) REFERENCES users (subject)
);

CREATE TABLE client_store
(
    subject       TEXT    NOT NULL UNIQUE PRIMARY KEY,
    name          TEXT    NOT NULL,
    secret        TEXT    NOT NULL UNIQUE,
    domain        TEXT    NOT NULL,
    owner_subject TEXT    NOT NULL,
    perms         TEXT    NOT NULL,
    public        BOOLEAN NOT NULL,
    sso           BOOLEAN NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT 1,

    FOREIGN KEY (owner_subject) REFERENCES users (subject)
);

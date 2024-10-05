CREATE TABLE users
(
    id              INTEGER  NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    subject         TEXT     NOT NULL UNIQUE,
    password        TEXT     NOT NULL,

    change_password BOOLEAN  NOT NULL,

    email           TEXT     NOT NULL,
    email_verified  BOOLEAN  NOT NULL,

    updated_at      DATETIME NOT NULL,
    registered      DATETIME NOT NULL,
    active          BOOLEAN  NOT NULL DEFAULT 1,

    name            TEXT     NOT NULL,
    picture         TEXT     NOT NULL DEFAULT '',
    website         TEXT     NOT NULL DEFAULT '',
    pronouns        TEXT     NOT NULL DEFAULT 'they/them',
    birthdate       DATE     NULL     DEFAULT NULL,
    zone            TEXT     NOT NULL DEFAULT 'UTC',
    locale          TEXT     NOT NULL DEFAULT 'en-US',

    login           TEXT     NOT NULL DEFAULT '',
    profile_url     TEXT     NOT NULL DEFAULT '',

    auth_type       INTEGER  NOT NULL,
    auth_namespace  TEXT     NOT NULL,
    auth_user       TEXT     NOT NULL,

    access_token    TEXT     NULL     DEFAULT NULL,
    refresh_token   TEXT     NULL     DEFAULT NULL,
    token_expiry    DATETIME NULL     DEFAULT NULL,

    otp_secret      TEXT     NOT NULL DEFAULT '',
    otp_digits      INTEGER  NOT NULL DEFAULT 0,

    to_delete       BOOLEAN  NOT NULL DEFAULT 0
);

CREATE INDEX users_subject ON users (subject);

CREATE TABLE roles
(
    id   INTEGER NOT NULL UNIQUE PRIMARY KEY AUTOINCREMENT,
    role TEXT    NOT NULL UNIQUE
);

CREATE TABLE users_roles
(
    role_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,

    FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT,
    FOREIGN KEY (user_id) REFERENCES users (id),

    CONSTRAINT user_role UNIQUE (role_id, user_id)
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

CREATE TABLE users
(
    subject        TEXT PRIMARY KEY UNIQUE NOT NULL,
    email          TEXT UNIQUE             NOT NULL,
    email_verified BOOLEAN DEFAULT 0       NOT NULL,
    roles          TEXT                    NOT NULL,
    userinfo       TEXT                    NOT NULL,
    access_token   TEXT,
    refresh_token  TEXT,
    expiry         DATETIME,
    updated_at     DATETIME                NOT NULL,
    active         BOOLEAN DEFAULT 1       NOT NULL
);

CREATE TABLE client_store
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    name    TEXT                    NOT NULL,
    secret  TEXT UNIQUE             NOT NULL,
    domain  TEXT                    NOT NULL,
    owner   TEXT                    NOT NULL,
    perms   TEXT                    NOT NULL,
    public  BOOLEAN                 NOT NULL,
    sso     BOOLEAN                 NOT NULL,
    active  BOOLEAN DEFAULT 1       NOT NULL,
    FOREIGN KEY (owner) REFERENCES users (subject)
);

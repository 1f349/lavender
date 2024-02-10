CREATE TABLE IF NOT EXISTS users
(
    subject        TEXT PRIMARY KEY UNIQUE NOT NULL,
    email          TEXT                    NOT NULL,
    email_verified INTEGER DEFAULT 0       NOT NULL,
    roles          TEXT                    NOT NULL,
    access_token   TEXT,
    refresh_token  TEXT,
    expiry         DATETIME,
    updated_at     DATETIME,
    active         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS client_store
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    name    TEXT                    NOT NULL,
    secret  TEXT UNIQUE             NOT NULL,
    domain  TEXT                    NOT NULL,
    owner   TEXT                    NOT NULL,
    perms   TEXT                    NOT NULL,
    public  INTEGER,
    sso     INTEGER,
    active  INTEGER DEFAULT 1,
    FOREIGN KEY (owner) REFERENCES users (subject)
);

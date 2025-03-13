CREATE TABLE oauth_sources
(
  namespace     TEXT    NOT NULL UNIQUE PRIMARY KEY,
  address       TEXT    NOT NULL,
  registration  BOOLEAN NOT NULL,
  button        BOOLEAN NOT NULL,
  client_id     TEXT    NOT NULL,
  client_secret TEXT    NOT NULL,
  client_scopes TEXT    NOT NULL
);

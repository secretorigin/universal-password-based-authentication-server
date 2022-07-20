CREATE TABLE new_users(
  new_user_id_ BIGSERIAL PRIMARY KEY,
  login_ TEXT UNIQUE NOT NULL,
  password_hash_ VARCHAR(64) NOT NULL,
  password_salt_ VARCHAR(32) NOT NULL,
  password_iterations_ INT NOT NULL
);

CREATE TABLE users(
  user_id_ BIGSERIAL PRIMARY KEY,
  login_ TEXT UNIQUE NOT NULL,
  password_hash_ VARCHAR(64) NOT NULL,
  password_salt_ VARCHAR(32) NOT NULL,
  password_iterations_ INT NOT NULL
);

CREATE TABLE tokens(
  token_id_ BIGSERIAL PRIMARY KEY,
  user_id_ BIGINT NOT NULL,
  salt_ varchar(32) NOT NULL,
  refresh_salt_ varchar(32) NOT NULL,
  creation_date DOUBLE PRECISION DEFAULT EXTRACT(EPOCH FROM now())
);
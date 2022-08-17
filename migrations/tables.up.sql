CREATE TABLE users(
  user_id_ BIGSERIAL PRIMARY KEY,
  login_ TEXT UNIQUE NOT NULL,
  password_hash_ VARCHAR(96) NOT NULL,
  password_iterations_ INT NOT NULL
);

CREATE TABLE tokens(
  token_id_ BIGSERIAL PRIMARY KEY,
  user_id_ BIGINT NOT NULL,
  salt_ varchar(32) NOT NULL,
  refresh_salt_ varchar(32) NOT NULL
);

CREATE TABLE temporary_passwords(
  temporary_password_id_ BIGSERIAL PRIMARY KEY,

  -- purposes: create (create user), 
  --           delete (delete user),
  --           token (create new token for the user),
  --           password (change password),
  --           login (change login)
  purposes_ TEXT NOT NULL,

  -- all data which you need to do this purpose
  data_ JSON

  password_ TEXT,
  salt_ varchar(32) NOT NULL
);
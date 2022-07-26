CREATE TABLE users(
  user_id_ BIGSERIAL PRIMARY KEY,
  login_ TEXT UNIQUE NOT NULL,
  password_hash_ VARCHAR(96) NOT NULL,
  password_iterations_ INT NOT NULL
);

CREATE TABLE tokens(
  token_id_ BIGSERIAL PRIMARY KEY,
  
  salt_ varchar(32) NOT NULL,
  refresh_salt_ varchar(32) NOT NULL
);

CREATE TABLE temporary_passwords(
  temporary_password_id_ BIGSERIAL PRIMARY KEY,
  password_ TEXT,

  salt_ varchar(32) NOT NULL,
  
  -- purposes: register, login, ...
  purpose_ TEXT NOT NULL,
  data_ JSON
);
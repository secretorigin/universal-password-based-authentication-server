CREATE TABLE users(
  user_id_ BIGSERIAL PRIMARY KEY,

  twofa_ BOOLEAN DEFAULT FALSE,

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

CREATE TABLE verification_codes(
  verification_code_id_ BIGSERIAL PRIMARY KEY,

  -- purposes: create (create user), 
  --           delete (delete user),
  --           token (create new token for the user),
  --           password (change password),
  --           login (change login)
  purpose_ TEXT NOT NULL,
  -- all data which you need to do this purpose
  data_ JSON,

  code_ TEXT,
  salt_ varchar(32) NOT NULL
);

CREATE TABLE invite_codes(
  invite_code_id_ BIGSERIAL PRIMARY KEY,
  code_ TEXT NOT NULL UNIQUE,
  creator_id_ BIGINT NOT NULL,
  used_ BOOLEAN DEFAULT FALSE,
  used_by_ BIGINT
);
<h1>universal-password-based-authentication-server</h1>

<h2>How to use?</h2>

- Create sql database and initialize tables from <b>./migrations</b> folder. Connection data for database must be written to the <b>./configs/db.local.json</b>:

  ```json
  {
    "host":"ip",
    "port":0,
    "name":"database name",
    "user":"user name",
    "password":"password"
  }
  ```

  This server is supposed to work with postgres.

- Initialize server with setting data in config <b>./configs/server.local.json</b> in this format:
  
  ```json
  {
    "host":"ip",
    "port": 0
  }
  ```

<h2>Database</h2>

Tables all tables you can see in the <b>./migrations</b> folder

- new_users: Table for new not confirmed users
- users: Table for users with their login data
- tokens: Table for access tokens
- temporary_passwords: Table for temporary passwords

<h2>Security</h2>

- PBKDF2 + SHA256 password encryption for saving in the database
- JWT tokens for giving access to the resource
- Temporary passwords to confirm special actions

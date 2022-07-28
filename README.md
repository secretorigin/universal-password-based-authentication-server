<h1>universal-password-based-authentication-server</h1>

- [API](https://github.com/p2034/universal-password-based-authentication-server/tree/main/api)
- [Database](#database)
- [Security](#security)
- [How to use](#how_to_use)

<a name="database">
<h2>Database</h2>

Tables all tables you can see in the <b>./migrations</b> folder

- new_users: Table for new not confirmed users
- users: Table for users with their login data
- tokens: Table for access tokens
- temporary_passwords: Table for temporary passwords

<a name="security">
<h2>Security</h2>

- PBKDF2 + SHA256 password encryption for saving in the database
- JWT tokens for giving access to the resource
- Temporary passwords to confirm special actions

<a name="how_to_use">
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

- Create functions for sending temparary passwords and set it (<b>settings.TemporaryPasswordSend</b>)

- Set temporary password regular expession (<b>settings.TemporaryPasswordRegex</b>)

- Set all 2FA <b>bool</b> variables you need:
	- <b>settings.PasswordChange2FA</b>
	- <b>settings.LoginChange2FA</b>
	- <b>settings.UserCreate2FA</b>
	- <b>settings.UserDelete2FA</b>
	- <b>settings.TokenGet2FA</b>

Login is some information, which is used for delivering temporary passwords to the user, it can be email, or phone number, or other, it just must be written as a string. You can change regular expression for login, changing <b>settings.LoginRegex</b>.

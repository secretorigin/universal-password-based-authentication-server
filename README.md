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
- verification_codes: Table for verification codes and purposes for them

<a name="security">
<h2>Security</h2>

- PBKDF2 + SHA256 password encryption for saving in the database
- JWT tokens for giving access to the resource
- Verification codes to confirm special actions

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

- Create functions for sending temparary passwords and set it (<b>settings.Conf.VerificationCodeSend</b>)

- Set verification codes regular expession (<b>./configs/server.json</b>).

- Set all 2FA <b>bool</b> variables you need in <b>./configs/server.json</b>.

Login is some information, which is used for delivering verification codes to the user, it can be email, or phone number, or other, it just must be written as a string. You can change regular expression for login in <b>./configs/server.json</b>.

And you can build and start server (in project directory):

```bash
make build
./bin/app
```

<h2>Problems:<h2>

There was large renaming temporary password in verification codes; temporary token in verification codes, mistakes can be in documentation.
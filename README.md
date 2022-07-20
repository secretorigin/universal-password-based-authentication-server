<h1>universal-password-based-authentication-server</h1>

<h1>How it works?</h1>

<h1>How to use?</h1>

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

- Initialize server with setting data in config:
  Write data in config <b>./configs/server.local.json</b> in this format:
  
  ```json
  {
    "host":"ip",
    "port": 0
  }
  ```
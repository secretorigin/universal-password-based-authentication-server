<h1>universal-password-based-authentication-server API</h1>

<h2>Why does it look like this?</h2>

I mean the names of the rest api handles and other.
We can classify handles in 2 ways:
1. Dependency on server authentication settings:
  - Depend: <b>/user/create</b>, <b>/user/delete</b>, <b>/password/change</b>, <b>/login/change</b>
    If they are enabled in server settings user must confirm this actions with <b>/confirm</b> request.
  - Not depend: <b>/token/get</b>, <b>/token/delete</b>, <b>/token/check</b>, <b>/token/update</b>, <b>/confirm</b>
    This requests can't be confirmed by <b>/confirm</b> request.
2. Flow:
  - User flow: <b>/user/create</b>, <b>/user/delete</b>, <b>/password/change</b>, <b>/login/change</b>, <b>/confirm</b>
    User directly interacts with them.
  - App flow: <b>/token/get</b>, <b>/token/delete</b>, <b>/token/check</b>, <b>/token/update</b>
    App must use this handles in the background.

In perfect way only Service servers interact with with handles: you can redirect https://service/login on https://local_auth_server/token/create etc. Handle /token/check by definition only needed by the server. Because of this you need to create special API-redirection server for your service.
<h1>universal-password-based-authentication-server</h1>
<h1>API</h1>

<h2>Why does it look like this?</h2>

We can classify handles in 2 ways:
1. Dependency on server authentication settings:
  - Depend. If they are enabled in server settings, user must confirm this actions with <b>/confirm</b> request: <b>/user/create</b>, <b>/user/delete</b>, <b>/password/change</b>, <b>/login/change</b>
  - Not depend. This requests can't be confirmed by <b>/confirm</b> request: <b>/token/get</b>, <b>/token/delete</b>, <b>/token/check</b>, <b>/token/update</b>, <b>/confirm</b>
2. Flow:
  - User flow. User directly interacts with them: <b>/user/create</b>, <b>/user/delete</b>, <b>/password/change</b>, <b>/login/change</b>, <b>/confirm</b>
  - App flow. App must use this handles in the background: <b>/token/get</b>, <b>/token/delete</b>, <b>/token/check</b>, <b>/token/update</b>

In perfect way only Service servers interact with this handles: you can redirect <b>service/login</b> to <b>local_auth_server/token/create</b> etc. Handle <b>/token/check</b> by definition only needed by the server. Because of this you need to create special API-redirection server for your service.

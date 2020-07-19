# auth service

At this time, you have a RESTful API server running at `http://127.0.0.1:3000`. It provides the following endpoints:
(`authReq`: "guid, accessToken, refreshToken" headers are required)

* `POST /v1/login`: authenticate a user and generate a JWT | json(username, password) && "guid" header are required
*	`GET /v1/refresh-tokens`: refresh tokens | authReq
*	`GET /v1/revoke-tokens`: delete refresh token | authReq
*	`GET /v1/revoke-all-tokens`: delete all refresh tokens | authReq

If you have `cURL` or some API client tools (e.g. [Postman](https://www.getpostman.com/)), you may try the following 
more complex scenarios:

```shell
# authenticate the user via: POST /v1/login
# Example guid: 9ab0d2dc-9459-41c8-9000-9dbade909f99
curl -X POST --cookie-jar refreshToken.txt  -H "guid: ..guid.." -H "Content-Type: application/json" -d '{"username":"user", "password":"pass"}' http://localhost:3000/v1/login
# should return a JWT token like: {"acceessToken":"...JWT token here..."} and "refresh-token" http-only cookie

# with the above JWT accessToken and refreshToken, you can access GET /v1/refresh-tokens route and refresh tokens
curl -X GET -b refreshToken.txt --cookie-jar refreshToken.txt -H "guid: ..guid.." -H "Authorization: Bearer ..accessToken.." http://localhost:3000/v1/refresh-tokens
# should return the same as previous (POST /v1/login) route but with new values

# delete current user's auth tokens
curl -X GET -b refreshToken.txt -H "guid: ..guid.." -H "Authorization: Bearer ..accessToken.." http://localhost:3000/v1/revoke-tokens
# should return HTTP Status 204 (No Content)

# delete current user's all auth tokens
curl -X GET -b refreshToken.txt -H "guid: ..guid.." -H "Authorization: Bearer ..accessToken.." http://localhost:3000/v1/revoke-all-tokens
# should return HTTP Status 204 (No Content)
```
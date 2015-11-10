# Akka Http + Spring OAuth2 + JWT

## get an access token

### client_credential
```
curl -u  client_id:client_secret -X POST "http://127.0.0.1:9000/oauth/token?grant_type=client_credentials&scope=something"
```
### password
```
curl -u  client_id:client_secret -X POST "http://127.0.0.1:9000/oauth/token?grant_type=password&scope=something&username=username&password=password"
```

#### response

```json
{
  "access_token": [SOME TOKEN],
  "expires_in": 43199,
  "scope": "something",
  "refresh_token": null,
  "token_type": "bearer"
}
```

given the access_token it is now possible to call the protected end-point:

```
curl -v -H "Authorization: Bearer [SOME TOKEN]"  -X GET  http://127.0.0.1:9000/account
```

### response
```json
{
  "username": "[THE AUTHENTICATED USERNAME]"
}
```

the returned username will be set to __client_id__ when using the _client_credentials_ flow and __username__ when using the _password_ flow.


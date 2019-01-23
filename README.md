# gocloak-echo
Keycloak handler &amp; middleware for echo

Use this together with the keycloak client [gocloak](https://github.com/Nerzal/gocloak)

```go
// AuthenticationHandler is used to authenticate with the api
type AuthenticationHandler interface {
	AuthenticateClient(Authenticate) (*gocloak.JWT, error)
	AuthenticateUser(Authenticate) (*gocloak.JWT, error)
	RefreshToken(Refresh) (*gocloak.JWT, error)
}
```

```go
// AuthenticationMiddleWare is used to validate the JWT
type AuthenticationMiddleWare interface {
	CheckToken(next echo.HandlerFunc) echo.HandlerFunc
	CheckScope(next echo.HandlerFunc) echo.HandlerFunc
}
```
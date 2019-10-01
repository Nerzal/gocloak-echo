package gocloakecho

import (
	"github.com/labstack/echo/v4"
)

const (
	// KeyRealm is used as realm key constant
	KeyRealm = "realm"
)

// AuthenticationMiddleWare is used to validate the JWT
type AuthenticationMiddleWare interface {
	// Decodes the token and checks if it is valid
	DecodeAndValidateToken(next echo.HandlerFunc) echo.HandlerFunc

	CheckToken(next echo.HandlerFunc) echo.HandlerFunc

	// The following 2 methods need higher permissions of the client in the realm
	CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc
	CheckScope(next echo.HandlerFunc) echo.HandlerFunc
}

package main

import (
	"net/http"

	"github.com/Nerzal/gocloak"
	"gitlab.com/fino/schufa/api/pkg/models"

	"github.com/labstack/echo"
)

// AuthenticationMiddleWare is used to validate the JWT
type AuthenticationMiddleWare interface {
	CheckToken(next echo.HandlerFunc) echo.HandlerFunc
	CheckScope(next echo.HandlerFunc) echo.HandlerFunc
}

type authenticationMiddleWare struct {
	gocloak      gocloak.GoCloak
	realm        string
	allowedScope string
}

// NewAuthenticationMiddleWare instantiates a new AuthenticationMiddleWare
func NewAuthenticationMiddleWare(gocloak gocloak.GoCloak, realm, allowedScope string) AuthenticationMiddleWare {
	return &authenticationMiddleWare{
		gocloak:      gocloak,
		realm:        realm,
		allowedScope: allowedScope,
	}
}

// CheckToken used to verify authorization tokens
func (auth *authenticationMiddleWare) CheckToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		err := auth.gocloak.ValidateToken(token, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, models.APIError{
				Code:    403,
				Message: "Invalid or malformed token",
				Detail:  "The token may be expired or malformed. Try to authorize again",
			})
		}

		return next(c)
	}
}

func (auth *authenticationMiddleWare) CheckScope(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// token := c.Request().Header.Get("Authorization")

		return next(c)
	}
}

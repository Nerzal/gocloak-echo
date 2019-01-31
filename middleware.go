package gocloakecho

import (
	"net/http"
	"strings"

	gocloak "github.com/Nerzal/gocloak"
	"github.com/Nerzal/gocloak/pkg/jwx"
	jwt "github.com/dgrijalva/jwt-go"

	"github.com/labstack/echo"
)

// AuthenticationMiddleWare is used to validate the JWT
type AuthenticationMiddleWare interface {
	CheckToken(next echo.HandlerFunc) echo.HandlerFunc
	CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc
	CheckScope(next echo.HandlerFunc) echo.HandlerFunc
}

type authenticationMiddleWare struct {
	gocloak           gocloak.GoCloak
	realm             string
	adminClientID     string
	adminClientSecret string
	allowedScope      string
	customHeaderName  *string
}

// NewAuthenticationMiddleWare instantiates a new AuthenticationMiddleWare
func NewAuthenticationMiddleWare(gocloak gocloak.GoCloak, realm, allowedScope, adminClientID, adminClientSecret string, customHeaderName *string) AuthenticationMiddleWare {
	return &authenticationMiddleWare{
		gocloak:           gocloak,
		realm:             realm,
		allowedScope:      allowedScope,
		customHeaderName:  customHeaderName,
		adminClientID:     adminClientID,
		adminClientSecret: adminClientSecret,
	}
}

// CheckTokenCustomHeader used to verify authorization tokens
func (auth *authenticationMiddleWare) CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get(*auth.customHeaderName)
		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		decodedToken, err := auth.stripBearerAndCheckToken(token, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token: " + err.Error(),
			})
		}

		if !decodedToken.Valid {
			return c.JSON(http.StatusForbidden, gocloak.APIError{
				Code:    http.StatusForbidden,
				Message: "Invalid Token",
			})
		}

		return next(c)
	}
}

func (auth *authenticationMiddleWare) stripBearerAndCheckToken(accessToken string, realm string) (*jwt.Token, error) {
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)
	token, err := auth.gocloak.LoginClient(auth.adminClientID, auth.adminClientSecret, realm)
	if err != nil {
		return nil, err
	}
	decodedToken, _, err := auth.gocloak.DecodeAccessToken(accessToken, token.AccessToken, realm)
	return decodedToken, err
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

		adminToken, err := auth.gocloak.LoginClient(auth.adminClientID, auth.adminClientSecret, auth.realm)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authentication failed",
			})
		}

		token = strings.Replace(token, "Bearer ", "", 1)
		decodedToken, _, err := auth.gocloak.DecodeAccessToken(token, adminToken.AccessToken, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token",
			})
		}

		if !decodedToken.Valid {
			return c.JSON(http.StatusForbidden, gocloak.APIError{
				Code:    http.StatusForbidden,
				Message: "Invalid Token",
			})
		}

		return next(c)
	}
}

func (auth *authenticationMiddleWare) CheckScope(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		adminToken, err := auth.gocloak.LoginClient(auth.adminClientID, auth.adminClientSecret, auth.realm)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authentication failed",
			})
		}

		token = strings.Replace(token, "Bearer ", "", 1)
		claims := &jwx.Claims{}
		_, err = auth.gocloak.DecodeAccessTokenCustomClaims(token, adminToken.AccessToken, auth.realm, claims)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token",
			})
		}

		if !strings.Contains(claims.Scope, auth.allowedScope) {
			return c.JSON(http.StatusForbidden, gocloak.APIError{
				Code:    http.StatusForbidden,
				Message: "Insufficient permissions to access the requested resource",
			})
		}

		return next(c)
	}
}

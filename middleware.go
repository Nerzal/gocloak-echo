package gocloakecho

import (
	"net/http"
	"strings"

	gocloak "github.com/Nerzal/gocloak"
	"github.com/Nerzal/gocloak/pkg/jwx"
	jwt "github.com/dgrijalva/jwt-go"

	"github.com/labstack/echo"
)

const (
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

type authenticationMiddleWare struct {
	gocloak          gocloak.GoCloak
	realm            string
	clientID         string
	clientSecret     string
	allowedScope     string
	customHeaderName *string
}

// NewAuthenticationMiddleWare instantiates a new AuthenticationMiddleWare.
func NewAuthenticationMiddleWare(gocloak gocloak.GoCloak, realm, clientID, clientSecret, allowedScope string, customHeaderName *string) AuthenticationMiddleWare {
	return &authenticationMiddleWare{
		gocloak:          gocloak,
		realm:            realm,
		allowedScope:     allowedScope,
		customHeaderName: customHeaderName,
		clientID:         clientID,
		clientSecret:     clientSecret,
	}
}

// CheckTokenCustomHeader used to verify authorization tokens
func (auth *authenticationMiddleWare) CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		realm := auth.realm

		if realm == "" {
			value, ok := c.Get(KeyRealm).(string)
			if ok {
				realm = value
			}
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		decodedToken, err := auth.stripBearerAndCheckToken(token, realm)
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

	decodedToken, _, err := auth.gocloak.DecodeAccessToken(accessToken, realm)
	return decodedToken, err
}

func (auth *authenticationMiddleWare) DecodeAndValidateToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		return next(c)
	}

}

// CheckToken used to verify authorization tokens
func (auth *authenticationMiddleWare) CheckToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		token = strings.Replace(token, "Bearer ", "", 1)
		result, err := auth.gocloak.RetrospectToken(token, auth.clientID, auth.clientSecret, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token:" + err.Error(),
			})
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: err.Error(),
			})
		}

		if !result.Active {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or expired Token",
			})
		}

		return next(c)
	}
}

func (auth *authenticationMiddleWare) CheckScope(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := ""
		if auth.customHeaderName != nil {
			token = c.Request().Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = c.Request().Header.Get("Authorization")
		}

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Authorization header missing",
			})
		}

		token = strings.Replace(token, "Bearer ", "", 1)
		claims := &jwx.Claims{}
		_, err := auth.gocloak.DecodeAccessTokenCustomClaims(token, auth.realm, claims)
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

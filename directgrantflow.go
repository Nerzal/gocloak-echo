package gocloakecho

import (
	"context"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v8"
	"github.com/Nerzal/gocloak/v8/pkg/jwx"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/labstack/echo/v4"
)

// NewDirectGrantMiddleware instantiates a new AuthenticationMiddleWare when using the Keycloak Direct Grant aka
// Resource Owner Password Credentials Flow
//
// see https://www.keycloak.org/docs/latest/securing_apps/index.html#_resource_owner_password_credentials_flow and
// https://tools.ietf.org/html/rfc6749#section-4.3 for more information about this flow
//noinspection GoUnusedExportedFunction
func NewDirectGrantMiddleware(ctx context.Context, gocloak gocloak.GoCloak, realm, clientID, clientSecret, allowedScope string, customHeaderName *string) AuthenticationMiddleWare {
	return &directGrantMiddleware{
		gocloak:          gocloak,
		realm:            realm,
		allowedScope:     allowedScope,
		customHeaderName: customHeaderName,
		clientID:         clientID,
		clientSecret:     clientSecret,
		ctx:              ctx,
	}
}

type directGrantMiddleware struct {
	gocloak          gocloak.GoCloak
	realm            string
	clientID         string
	clientSecret     string
	allowedScope     string
	customHeaderName *string
	ctx              context.Context
}

// CheckTokenCustomHeader used to verify authorization tokens
func (auth *directGrantMiddleware) CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc {
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

func (auth *directGrantMiddleware) stripBearerAndCheckToken(accessToken string, realm string) (*jwt.Token, error) {
	accessToken = extractBearerToken(accessToken)

	decodedToken, _, err := auth.gocloak.DecodeAccessToken(auth.ctx, accessToken, realm, "")
	return decodedToken, err
}

func (auth *directGrantMiddleware) DecodeAndValidateToken(next echo.HandlerFunc) echo.HandlerFunc {
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
func (auth *directGrantMiddleware) CheckToken(next echo.HandlerFunc) echo.HandlerFunc {
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

		token = extractBearerToken(token)

		if token == "" {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Bearer Token missing",
			})
		}

		result, err := auth.gocloak.RetrospectToken(auth.ctx, token, auth.clientID, auth.clientSecret, auth.realm)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or malformed token:" + err.Error(),
			})
		}

		if !*result.Active {
			return c.JSON(http.StatusUnauthorized, gocloak.APIError{
				Code:    403,
				Message: "Invalid or expired Token",
			})
		}

		return next(c)
	}
}

func extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func (auth *directGrantMiddleware) CheckScope(next echo.HandlerFunc) echo.HandlerFunc {
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

		token = extractBearerToken(token)
		claims := &jwx.Claims{}
		_, err := auth.gocloak.DecodeAccessTokenCustomClaims(auth.ctx, token, auth.realm, "", claims)
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

package gocloakecho

import (
	"errors"
	"net/http"

	"github.com/Nerzal/gocloak/v3"
)

// AuthenticationHandler is used to authenticate with the api
type AuthenticationHandler interface {
	AuthenticateClient(Authenticate) (*JWT, error)
	AuthenticateUser(Authenticate) (*JWT, error)
	RefreshToken(Refresh) (*JWT, error)
}

type authenticationHandler struct {
	gocloak gocloak.GoCloak
	realm   *string
}

// NewAuthenticationHandler instantiates a new AuthenticationHandler
// Setting realm is optional
func NewAuthenticationHandler(gocloak gocloak.GoCloak, realm *string) AuthenticationHandler {
	return &authenticationHandler{
		gocloak: gocloak,
		realm:   realm,
	}
}

func (handler *authenticationHandler) AuthenticateClient(requestData Authenticate) (*JWT, error) {
	realm := requestData.Realm
	if realm == "" {
		realm = *handler.realm
	}

	response, err := handler.gocloak.LoginClient(requestData.ClientID, requestData.ClientSecret, realm)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    403,
			Message: err.Error(),
		}
	}

	if response.AccessToken == "" {
		return nil, errors.New("Authentication failed")
	}

	return &JWT{
		AccessToken:      response.AccessToken,
		ExpiresIn:        response.ExpiresIn,
		NotBeforePolicy:  response.NotBeforePolicy,
		RefreshExpiresIn: response.RefreshExpiresIn,
		RefreshToken:     response.RefreshToken,
		Scope:            response.Scope,
		SessionState:     response.SessionState,
		TokenType:        response.TokenType,
	}, nil
}

func (handler *authenticationHandler) AuthenticateUser(requestData Authenticate) (*JWT, error) {
	realm := requestData.Realm
	if realm == "" {
		realm = *handler.realm
	}

	response, err := handler.gocloak.Login(requestData.ClientID, requestData.ClientSecret, realm, *requestData.UserName, *requestData.Password)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    http.StatusForbidden,
			Message: err.Error(),
		}
	}

	if response.AccessToken == "" {
		return nil, errors.New("Authentication failed")
	}

	return &JWT{
		AccessToken:      response.AccessToken,
		ExpiresIn:        response.ExpiresIn,
		NotBeforePolicy:  response.NotBeforePolicy,
		RefreshExpiresIn: response.RefreshExpiresIn,
		RefreshToken:     response.RefreshToken,
		Scope:            response.Scope,
		SessionState:     response.SessionState,
		TokenType:        response.TokenType,
	}, nil
}

func (handler *authenticationHandler) RefreshToken(requestData Refresh) (*JWT, error) {
	realm := requestData.Realm
	if realm == "" {
		realm = *handler.realm
	}

	response, err := handler.gocloak.RefreshToken(requestData.RefreshToken, requestData.ClientID, requestData.ClientSecret, requestData.Realm)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    http.StatusForbidden,
			Message: "Failed to refresh token",
		}
	}

	if response.AccessToken == "" {
		return nil, errors.New("Authentication failed")
	}

	return &JWT{
		AccessToken:      response.AccessToken,
		ExpiresIn:        response.ExpiresIn,
		NotBeforePolicy:  response.NotBeforePolicy,
		RefreshExpiresIn: response.RefreshExpiresIn,
		RefreshToken:     response.RefreshToken,
		Scope:            response.Scope,
		SessionState:     response.SessionState,
		TokenType:        response.TokenType,
	}, nil
}

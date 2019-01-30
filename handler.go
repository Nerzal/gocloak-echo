package gocloakecho

import (
	"errors"

	"github.com/Nerzal/gocloak"
)

// AuthenticationHandler is used to authenticate with the api
type AuthenticationHandler interface {
	AuthenticateClient(Authenticate) (*JWT, error)
	AuthenticateUser(Authenticate) (*JWT, error)
	RefreshToken(Refresh) (*JWT, error)
}

type authenticationHandler struct {
	gocloak gocloak.GoCloak
	realm   string
}

// NewAuthenticationHandler instantiates a new AuthenticationHandler
func NewAuthenticationHandler(gocloak gocloak.GoCloak, realm string) AuthenticationHandler {
	return &authenticationHandler{
		gocloak: gocloak,
		realm:   realm,
	}
}

func (handler *authenticationHandler) AuthenticateClient(requestData Authenticate) (*JWT, error) {
	response, err := handler.gocloak.LoginClient(requestData.ClientID, requestData.ClientSecret, handler.realm)
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
	response, err := handler.gocloak.Login(requestData.ClientID, requestData.ClientSecret, handler.realm, *requestData.UserName, *requestData.Password)
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

func (handler *authenticationHandler) RefreshToken(requestData Refresh) (*JWT, error) {
	response, err := handler.gocloak.RefreshToken(requestData.RefreshToken, requestData.ClientID, requestData.ClientSecret, handler.realm)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    403,
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

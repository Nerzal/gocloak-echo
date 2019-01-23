package gocloakecho

import (
	"github.com/Nerzal/gocloak"
)

// AuthenticationHandler is used to authenticate with the api
type AuthenticationHandler interface {
	AuthenticateClient(Authenticate) (*gocloak.JWT, error)
	AuthenticateUser(Authenticate) (*gocloak.JWT, error)
	RefreshToken(Refresh) (*gocloak.JWT, error)
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

func (handler *authenticationHandler) AuthenticateClient(requestData Authenticate) (*gocloak.JWT, error) {
	response, err := handler.gocloak.LoginClient(requestData.ClientID, requestData.ClientSecret, handler.realm)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    403,
			Message: err.Error(),
		}
	}

	return &gocloak.JWT{
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

func (handler *authenticationHandler) AuthenticateUser(requestData Authenticate) (*gocloak.JWT, error) {
	response, err := handler.gocloak.Login(requestData.ClientID, requestData.ClientSecret, handler.realm, *requestData.UserName, *requestData.Password)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    403,
			Message: err.Error(),
		}
	}

	return &gocloak.JWT{
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

func (handler *authenticationHandler) RefreshToken(requestData Refresh) (*gocloak.JWT, error) {
	response, err := handler.gocloak.RefreshToken(requestData.RefreshToken, requestData.ClientID, handler.realm)
	if err != nil {
		return nil, gocloak.APIError{
			Code:    403,
			Message: "Failed to refresh token",
		}
	}

	return &gocloak.JWT{
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

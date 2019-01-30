package gocloakecho

// Authenticate holds authentication information
type Authenticate struct {
	ClientID     string  `json:"clientID"`
	ClientSecret string  `json:"clientSecret"`
	UserName     *string `json:"username,omitempty"`
	Password     *string `json:"password,omitempty"`
}

// Refresh is used to refresh the JWT
type Refresh struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RefreshToken string `json:"refreshToken"`
}

// JWT is a JWT
type JWT struct {
	AccessToken      string `json:"accessToken"`
	ExpiresIn        int    `json:"expiresIn"`
	RefreshExpiresIn int    `json:"refreshExpiresIn"`
	RefreshToken     string `json:"refreshToken"`
	TokenType        string `json:"tokenType"`
	NotBeforePolicy  int    `json:"notBeforePolicy"`
	SessionState     string `json:"sessionState"`
	Scope            string `json:"scope"`
}

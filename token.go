package main

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
	RefreshToken string `json:"refreshToken"`
}

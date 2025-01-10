package lark

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://open.feishu.cn/open-apis/authen/v1/authorize"                 // 获取授权登录授权码
	tokenURL        string = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"         // 获取 user_access_token
	refreshTokenURL string = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token" // 刷新 user_access_token
	endpointProfile string = "https://open.feishu.cn/open-apis/authen/v1/user_info"                 // 获取用户信息
)

// Provider is the implementation of `goth.Provider` for accessing Lark
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string

	appAccessToken *appAccessToken
}

func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:      clientKey,
		Secret:         secret,
		CallbackURL:    callbackURL,
		providerName:   "lark",
		appAccessToken: &appAccessToken{},
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	}
	return c
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	// 生成授权登录 URL
	u, err := url.Parse(p.config.AuthCodeURL(state))
	if err != nil {
		panic(err)
	}
	query := u.Query()
	query.Del("response_type")
	query.Del("client_id")
	query.Add("app_id", p.ClientKey)
	u.RawQuery = query.Encode()

	return &Session{
		AuthURL: u.String(),
	}, nil
}

func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	return s, json.NewDecoder(strings.NewReader(data)).Decode(s)
}

func (p *Provider) Debug(b bool) {
}

type getAccessTokenResp struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	if err := p.GetAppAccessToken(p.ClientKey, p.Secret); err != nil {
		return nil, fmt.Errorf("failed to get app access token: %w", err)
	}
	reqBody := strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"` + refreshToken + `"}`)

	req, err := http.NewRequest(http.MethodPost, refreshTokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.appAccessToken.Token))

	resp, err := p.Client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code while refreshing token: %d", resp.StatusCode)
	}

	var oauthResp commResponse[getAccessTokenResp]
	err = json.NewDecoder(resp.Body).Decode(&oauthResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refreshed token: %w", err)
	}
	if oauthResp.Code != 0 {
		return nil, fmt.Errorf("failed to refresh token: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	token := oauth2.Token{
		AccessToken:  oauthResp.Data.AccessToken,
		RefreshToken: oauthResp.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(oauthResp.Data.ExpiresIn) * time.Second),
	}

	return &token, nil
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

type larkUser struct {
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"enterprise_email"`
	AvatarURL string `json:"avatar_url"`
	Mobile    string `json:"mobile,omitempty"`
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}
	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, fmt.Errorf("%s failed to create request: %w", p.providerName, err)
	}
	req.Header.Set("Authorization", "Bearer "+user.AccessToken)

	resp, err := p.Client().Do(req)
	if err != nil {
		return user, fmt.Errorf("%s failed to get user information: %w", p.providerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, fmt.Errorf("failed to read response body: %w", err)
	}

	var oauthResp commResponse[larkUser]
	if err = json.Unmarshal(responseBytes, &oauthResp); err != nil {
		return user, fmt.Errorf("failed to decode user info: %w", err)
	}
	if oauthResp.Code != 0 {
		return user, fmt.Errorf("failed to get user info: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	u := oauthResp.Data
	user.UserID = u.UserID
	user.Name = u.Name
	user.Email = u.Email
	user.AvatarURL = u.AvatarURL
	user.NickName = u.Name

	if err = json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}
	return user, nil
}

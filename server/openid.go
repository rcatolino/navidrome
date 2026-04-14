package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"path"

	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
)

var _state_key = GetRand128()

func GetRand128() (key [32]byte) {
	rand.Read(key[:])
	return key
}

// 'Relying party' implementation of openid connect 'Authorization Code Flow'
// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth

func (s *Server) mountOpenidConnectRoutes() chi.Router {
	r := s.router
	return r.Route(path.Join(conf.Server.BasePath, "/auth"), func(r chi.Router) {
		log.Warn("Login rate limit is disabled! Consider enabling it to be protected against brute-force attacks")
		r.Get("/ssologin", ssologin())
		r.Get("/ssocallback", ssocallback(s.ds))
	})
}

func ssocallback(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		clientUniqueId, exists := request.ClientUniqueIdFrom(r.Context())
		if !exists {
			log.Error("/auth_callback: Expected client id key in context is missing")
			http.Redirect(w, r, "/", 302)
			return
		}

		// See https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
		if values.Has("error") {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Authentication error (%s) %s\n", values.Get("error"), values.Get("error_description"))
			return
		}

		if !values.Has("session_state") || !values.Has("code") {
			w.WriteHeader(401)
			w.Write([]byte("Unauthorized\n"))
			return
		}

		// See RFC 6749 Sections 4.1.2 and 10.12.
		session_state := values.Get("session_state")
		state := values.Get("state")
		code := values.Get("code")
		log.Debug("Auth callback url.", "state", state, "session_state", session_state, "code", code)
		if !CheckStateToken(clientUniqueId, state) {
			log.Info("Auth callback: Error validating state with client id", "state", state, "clientId", clientUniqueId)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		qp := values.Get("qp")
		token, err := GetIdToken(code, qp)
		if err != nil {
			log.Info("Auth callback: GetIdToken error : %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		res, err := validateToken(cfg, token.IdToken)
		if err != nil {
			log.Info("Auth callback: error validating id token: %s", err)
			w.WriteHeader(401)
			w.Write([]byte("Authentication error\n"))
			return
		}

		sub, username, err := utils.CheckClaims(cfg, res)
		if err != nil {
			log.Info("Auth callback: error checking token claims: %s", err)
			w.WriteHeader(403)
			w.Write([]byte("Authorization error\n"))
			return
		}

		middlewares.Sessions.CreateSession(session_id, sub, username)
		// Redirect to original url ?
		originalQp, err := base64.URLEncoding.DecodeString(qp)
		var redirectUri string
		if err != nil {
			log.Info("Warning: error decoding original query parameters: %s", err)
			redirectUri = "/"
		} else {
			redirectUri = fmt.Sprintf("/?%s", string(originalQp))
		}
		log.Info("Redirecting to '%s'", redirectUri)
		http.Redirect(w, r, redirectUri, 302)

	}
}

func ssologin() func(w http.ResponseWriter, r *http.Request) {
	// Triggers an authentication flow following https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	return func(w http.ResponseWriter, r *http.Request) {
		clientUniqueId, exists := request.ClientUniqueIdFrom(r.Context())
		if !exists {
			log.Fatal("OpenID auth bug: clientUniqueId not set. The ClientUniqueId middleware should be run before authentication.")
		}
		queryParams := base64.URLEncoding.EncodeToString([]byte(r.URL.Query().Encode()))
		url := fmt.Sprintf(
			"%s?response_type=code&client_id=%s&scope=openid%%20roles&redirect_uri=%s/auth/ssocallback%%3fqp=%s&state=%s",
			conf.Server.OpenID.AuthorizationEndpoint,
			conf.Server.OpenID.ClientId,
			conf.Server.BaseURL,
			queryParams,
			MakeStateToken(clientUniqueId),
		)

		log.Info("Auth middleware, redirecting to : %s", url)
		http.Redirect(w, r, url, 302)
	}
}

func GetIdToken(code string, qp string) (*TokenResponse, error) {
	// See https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
	/*
		req, err := http.NewRequest("POST", cfg.OidcTokenUrl, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Add("Authorization", fmt.Sprintf("Basic %s", cfg.BasicAuthToken))
		req.SetBasicAuth()
	*/

	redirectUri := fmt.Sprintf("%s/auth_callback?qp=%s", cfg.FullUrl, qp)
	log.Printf("GetIdToken with redirectUri %s", redirectUri)
	resp, err := http.PostForm(cfg.BasicAuthTokenUrl, url.Values{
		"grant_type": {"authorization_code"},
		// "client_id":    {cfg.OidcClientId},
		"code":         {code},
		"redirect_uri": {redirectUri},
	})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 200 {
		var token TokenResponse
		defer resp.Body.Close()
		if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
			return nil, err
		}

		if !strings.EqualFold(token.TokenType, "Bearer") {
			return nil, fmt.Errorf("unexpected token type '%s'", token.TokenType)
		}

		return &token, nil
	} else if resp.StatusCode == 400 {
		var error ErrorResponse
		defer resp.Body.Close()
		if err = json.NewDecoder(resp.Body).Decode(&error); err != nil {
			return nil, err
		}

		log.Printf("Auth callback: GetIdToken invalid request : %s %s %s", error.Error, error.ErrorDescription, error.ErrorUri)
		return nil, errors.New(error.Error)
	}

	return nil, fmt.Errorf("unexpected response code %d", resp.StatusCode)
}

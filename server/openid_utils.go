package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/log"
)

func MakeStateToken(session_id string) string {
	mac := hmac.New(sha256.New, _state_key[:])

	// state is [IV(0-16),MAC(16-48)]
	var iv [16]byte
	ivlen, err := rand.Read(iv[:])
	if err != nil || ivlen < 16 {
		log.Fatal("Error reading random bytes", "error", err)
	}
	mac.Write(iv[:])
	mac.Write([]byte(session_id))
	state := mac.Sum(iv[:])
	log.Debug("Make state token", "ephemeralKey", _state_key, "iv", iv, "state", state, "stateLen", len(state))
	return base64.URLEncoding.EncodeToString(state)
}

func CheckStateToken(session_id string, b64state string) bool {
	mac := hmac.New(sha256.New, _state_key[:])

	state, err := base64.URLEncoding.DecodeString(b64state)
	if err != nil {
		log.Error("CheckStateToken error : state is not properly base64 encoded")
		return false
	}

	if len(state) != mac.Size()+16 {
		log.Error("CheckStateToken error : unexpected state length", "expected", mac.Size()+16, "got", len(state))
		return false
	}

	iv := state[:16]
	mac.Write(iv)
	mac.Write([]byte(session_id))
	stateMac := mac.Sum(nil)
	return hmac.Equal(state[16:], stateMac)
}

func checkClaims(token *jwt.Token) (sub, username string, err error) {
	sub, err = token.Claims.GetSubject()
	if err != nil {
		log.Info("Token valid, but subject claim is missing.")
		return "", "", err
	}

	mapClaims, valid := token.Claims.(jwt.MapClaims)
	if !valid {
		return "", "", fmt.Errorf("missing claims in id token for sub %s", sub)
	}

	username, exists := mapClaims["preferred_username"].(string)
	if !exists {
		return "", "", fmt.Errorf("missing 'preferred_username' claim for sub %s", sub)
	}

	resources, exists := mapClaims["resource_access"].(map[string]any)
	if !exists {
		return "", "", fmt.Errorf("missing 'resource_access' claim for sub %s. Claims : %v", sub, mapClaims)
	}
	if orwell_res, present := resources[conf.Server.OpenID.ClientId].(map[string]any); !present {
		return "", "", fmt.Errorf("missing ressource '%s' in 'resource_access' claim %s", conf.Server.OpenID.ClientId, resources)
	} else if roles, present := orwell_res["roles"].([]any); !present {
		return "", "", fmt.Errorf("missing roles in client resources: %v", orwell_res)
	} else if !slices.Contains(roles, "user") {
		return "", "", fmt.Errorf("role 'user' is not among the user roles: %v", roles)
	}

	return sub, username, nil
}

func validateToken(tokenString string) (*jwt.Token, error) {
	// See https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		var defaultKey []byte
		// 1: decrypt : not supported
		// 2: check issuer
		iss, err := token.Claims.GetIssuer()
		if err != nil {
			return defaultKey, err
		} else if iss != conf.Server.OpenID.Issuer {
			return defaultKey, fmt.Errorf("unexpected issuer '%s' != '%s'", iss, conf.Server.OpenID.Issuer)
		}

		// 3: check audience
		aud, err := token.Claims.GetAudience()
		if err != nil {
			return defaultKey, err
		} else if !slices.Contains(aud, conf.Server.OpenID.ClientId) {
			return defaultKey, fmt.Errorf("missing audience in '%s' (expected '%s')", aud, conf.Server.OpenID.ClientId)
		}

		// 4,5 : No extensions

		// 7: validate algorithm
		alg := token.Method.Alg()
		if alg != conf.Server.OpenID.Alg {
			return defaultKey, fmt.Errorf("unexpected validation algorithm '%s' != '%s'", alg, conf.Server.OpenID.Alg)
		}

		// 9: Validate time
		exp, err := token.Claims.GetExpirationTime()
		if err != nil {
			return defaultKey, err
		}

		if time.Now().After(exp.Time) {
			return defaultKey, fmt.Errorf("token expiration date %v is in the past", exp)
		}

		// 10: Validate iat
		iat, err := token.Claims.GetIssuedAt()
		if err != nil {
			return defaultKey, err
		}
		if iat.Time.After(time.Now()) {
			return defaultKey, fmt.Errorf("token issued_at date %v is in the future", iat.Time)
		}

		// 11: Validate nonce
		// TODO ? or maybe not ?

		// 12: validate acr. Again : WTF is this ?

		// 13: validate auth_time: not supported

		// 6 & 8: validation done using the configured key or the client secret for hmac :
		kid := token.Header["kid"]
		if strings.HasPrefix(conf.Server.OpenID.Alg, "HS") {
			// Validation with HS--- and client secret
			return []byte(conf.Server.OpenID.ClientSecret), nil
		} else if kid == conf.Server.OpenID.PublicKeyId {
			validAsymmetricKey, err := jwt.ParseECPublicKeyFromPEM([]byte(conf.Server.OpenID.PublicKey))
			if err != nil {
				return defaultKey, err
			}

			return validAsymmetricKey, nil
		}

		return defaultKey, fmt.Errorf("unexpected validation key id '%s'. Expected '%s'", kid, conf.Server.OpenID.PublicKeyId)
	})

	return token, err
}

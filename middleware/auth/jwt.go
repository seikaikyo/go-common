// Package auth provides Logto JWT authentication middleware.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/seikaikyo/go-common/response"
)

type contextKey string

const UserIDKey contextKey = "user_id"

// JWTConfig holds the Logto JWT validation parameters.
type JWTConfig struct {
	LogtoEndpoint    string
	LogtoAPIResource string
}

type jwksCache struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	ttl     time.Duration
}

var cache = &jwksCache{
	keys: make(map[string]*rsa.PublicKey),
	ttl:  1 * time.Hour,
}

// RequireJWT validates Logto-issued RS256 JWT tokens.
func RequireJWT(cfg JWTConfig) func(http.Handler) http.Handler {
	jwksURL := strings.TrimRight(cfg.LogtoEndpoint, "/") + "/oidc/jwks"
	expectedIssuer := strings.TrimRight(cfg.LogtoEndpoint, "/") + "/oidc"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				response.Err(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			parseOpts := []jwt.ParserOption{
				jwt.WithAudience(cfg.LogtoAPIResource),
				jwt.WithIssuer(expectedIssuer),
			}

			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				kid, _ := t.Header["kid"].(string)
				return getKey(jwksURL, kid)
			}, parseOpts...)

			// Key rotation retry
			if err != nil {
				cache.mu.Lock()
				cache.fetched = time.Time{}
				cache.mu.Unlock()

				token, err = jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
					if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
					}
					kid, _ := t.Header["kid"].(string)
					return getKey(jwksURL, kid)
				}, parseOpts...)
			}

			if err != nil || !token.Valid {
				response.Err(w, http.StatusUnauthorized, "invalid token")
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				response.Err(w, http.StatusUnauthorized, "invalid claims")
				return
			}

			sub, _ := claims["sub"].(string)
			if sub == "" {
				response.Err(w, http.StatusUnauthorized, "missing sub claim")
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, sub)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts the authenticated user ID from request context.
func GetUserID(ctx context.Context) string {
	id, _ := ctx.Value(UserIDKey).(string)
	return id
}

func getKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	cache.mu.RLock()
	if key, ok := cache.keys[kid]; ok && time.Since(cache.fetched) < cache.ttl {
		cache.mu.RUnlock()
		return key, nil
	}
	cache.mu.RUnlock()
	return fetchJWKS(jwksURL, kid)
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJWKS(jwksURL, kid string) (*rsa.PublicKey, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if key, ok := cache.keys[kid]; ok && time.Since(cache.fetched) < cache.ttl {
		return key, nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAKey(k)
		if err != nil {
			slog.Warn("skip JWKS key", "kid", k.Kid, "error", err)
			continue
		}
		newKeys[k.Kid] = pub
	}

	cache.keys = newKeys
	cache.fetched = time.Now()

	key, ok := newKeys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}
	return key, nil
}

func parseRSAKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

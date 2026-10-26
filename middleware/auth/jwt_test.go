package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testAudience = "https://api.example.test"

type fakeLogto struct {
	srv    *httptest.Server
	key    *ecdsa.PrivateKey
	hits   atomic.Int32
	status atomic.Int32
}

func newFakeLogto(t *testing.T) *fakeLogto {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeLogto{key: key}
	f.status.Store(http.StatusOK)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if code := int(f.status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		enc := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "EC", "crv": "P-384",
			"x": enc.EncodeToString(key.X.FillBytes(make([]byte, 48))),
			"y": enc.EncodeToString(key.Y.FillBytes(make([]byte, 48))),
		}}})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLogto) token(t *testing.T, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES384, jwt.MapClaims{
		"sub": "user-1",
		"iss": f.srv.URL + "/oidc",
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func resetCache() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.keys = make(map[string]crypto.PublicKey)
	cache.fetched = time.Time{}
	cache.attempted = time.Time{}
}

func call(t *testing.T, h http.Handler, bearer string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func handlerFor(f *fakeLogto) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return RequireJWT(JWTConfig{LogtoEndpoint: f.srv.URL, LogtoAPIResource: testAudience})(ok)
}

func TestValidTokenAccepted(t *testing.T) {
	resetCache()
	f := newFakeLogto(t)
	if code := call(t, handlerFor(f), f.token(t, "k1")); code != http.StatusNoContent {
		t.Fatalf("valid token: got %d", code)
	}
}

func TestBadTokensDoNotHammerJWKS(t *testing.T) {
	resetCache()
	f := newFakeLogto(t)
	h := handlerFor(f)
	if code := call(t, h, f.token(t, "k1")); code != http.StatusNoContent {
		t.Fatalf("warm-up: got %d", code)
	}
	for i := 0; i < 50; i++ {
		_ = call(t, h, "garbage.token.value")
		_ = call(t, h, f.token(t, "unknown-kid"))
	}
	// The warm-up fetch is the only one; unknown kids within the interval must not refetch.
	if got := f.hits.Load(); got != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", got)
	}
}

func TestFailingJWKSKeepsCachedKeys(t *testing.T) {
	resetCache()
	f := newFakeLogto(t)
	h := handlerFor(f)
	if code := call(t, h, f.token(t, "k1")); code != http.StatusNoContent {
		t.Fatalf("warm-up: got %d", code)
	}
	// Cache expired and Logto now failing: the held key must still verify.
	cache.mu.Lock()
	cache.fetched = time.Now().Add(-2 * time.Hour)
	cache.attempted = time.Time{}
	cache.mu.Unlock()
	f.status.Store(http.StatusTooManyRequests)
	if code := call(t, h, f.token(t, "k1")); code != http.StatusNoContent {
		t.Fatalf("stale key during outage: got %d", code)
	}
}

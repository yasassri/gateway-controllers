package jwtauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestJWTAuthPolicy_HappyPath_RemoteJWKS_IssuerNameAudienceScope(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"aud":   "api-audience",
		"scope": "read write",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["audiences"] = []interface{}{"api-audience"}
	params["requiredScopes"] = []interface{}{"read"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_HappyPath_AudienceArray_AndScpArray(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"aud": []interface{}{"api-audience", "secondary-audience"},
		"scp": []interface{}{"read", "write"},
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["audiences"] = []interface{}{"api-audience"}
	params["requiredScopes"] = []interface{}{"write"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_RequiredScopes_OR_MatchesOne(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token has only "read"; policy requires either "read" or "admin". OR
	// semantics means one match is enough.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["requiredScopes"] = []interface{}{"read", "admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_RequiredScopes_OR_MatchesNone(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token has neither of the required scopes → auth fails.
	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["issuers"] = []interface{}{"km-primary"}
	params["requiredScopes"] = []interface{}{"write", "admin"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_HappyPath_CustomHeaderName_AndPrefix(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["headerName"] = "X-Auth-Token"
	params["authHeaderPrefix"] = "JWT"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("X-Auth-Token", "JWT", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_HappyPath_LocalCert_WithClaimMappings_AndUserIdClaim(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub":      "user-123",
		"iss":      "https://issuer.example.com",
		"username": "alice",
		"email":    "alice@example.com",
	}, "test-kid")

	params := newRemoteParams("http://invalid.local/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name":   "km-local",
			"issuer": "https://issuer.example.com",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, publicKey),
				},
			},
		},
	}
	params["claimMappings"] = map[string]interface{}{
		"email": "X-User-Email",
	}
	params["userIdClaim"] = "username"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)

	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if mods.HeadersToSet["X-User-Email"] != "alice@example.com" {
		t.Fatalf("expected X-User-Email header to be set")
	}
	if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.Subject != "alice" {
		t.Fatalf("expected AuthContext.Subject to be set from userIdClaim")
	}
}

func TestJWTAuthPolicy_Negative_MissingAuthorizationHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	params["onFailureStatusCode"] = 403
	params["errorMessageFormat"] = "plain"
	params["errorMessage"] = "missing auth"

	ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
	assertAuthFailure(t, ctx, action, 403)

	resp := action.(policy.ImmediateResponse)
	if string(resp.Body) != "missing auth" {
		t.Fatalf("expected plain error body")
	}
}

func TestJWTAuthPolicy_Negative_WrongAuthorizationScheme(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["authHeaderScheme"] = "Bearer"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "JWT", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_MalformedJWT(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", "not.a.jwt"))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_MissingAlgHeader(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTokenWithoutAlgHeader(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Negative_DisallowedAlgorithm verifies that algorithms outside the
// hardcoded supported set (RS256, PS256, ES256) are rejected even when a valid key is present.
// RS384 is chosen as a representative unsupported-but-parseable algorithm.
func TestJWTAuthPolicy_Negative_DisallowedAlgorithm(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Mint an RS384 token (not in the hardcoded supportedAlgorithms set).
	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign RS384 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Negative_KidNotFoundInJWKS(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "known-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "missing-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_ExpWithinLeeway_Accepts(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-10 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Edge_ExpBeyondLeeway_Rejects(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"exp": time.Now().Add(-45 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_NbfWithinLeeway_Accepts(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(10 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Edge_NbfBeyondLeeway_Rejects(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
		"nbf": time.Now().Add(45 * time.Second).Unix(),
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["leeway"] = "30s"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Edge_NegativeRetryCount_NoPanic(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksFetchRetryCount"] = -1
	params["jwksFetchTimeout"] = "20ms"
	params["jwksFetchRetryInterval"] = "1ms"

	var (
		ctx    *policy.RequestHeaderContext
		action policy.RequestHeaderAction
	)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("OnRequestHeaders must not panic for invalid retry count: %v", recovered)
		}
		assertAuthFailure(t, ctx, action, 401)
	}()

	ctx, action = executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
}

func TestJWTAuthPolicy_Edge_RetryEventuallySucceeds(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		count := atomic.AddInt32(&requestCount, 1)
		if count <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksFetchRetryCount"] = 3
	params["jwksFetchRetryInterval"] = "1ms"
	params["jwksFetchTimeout"] = "100ms"

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)

	if got := atomic.LoadInt32(&requestCount); got != 3 {
		t.Fatalf("expected 3 JWKS fetch attempts, got %d", got)
	}
}

func TestJWTAuthPolicy_Edge_JWKSCacheHit_SkipsRefetch(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksCacheTtl"] = "1m"

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("expected exactly one JWKS fetch due to cache hit, got %d", got)
	}
}

func TestJWTAuthPolicy_Edge_JWKSCacheExpiry_Refetches(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	var requestCount int32

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&requestCount, 1)
		writeJWKSResponse(t, w, publicKey, "test-kid")
	}))
	defer jwksServer.Close()

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["jwksCacheTtl"] = "15ms"

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	p := mustGetPolicy(t, params)

	ctx1 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action1 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx1, params)
	assertAuthSuccess(t, ctx1, action1)

	time.Sleep(25 * time.Millisecond)

	ctx2 := createMockRequestHeaderContext(authHeader("Authorization", "Bearer", token))
	action2 := p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx2, params)
	assertAuthSuccess(t, ctx2, action2)

	if got := atomic.LoadInt32(&requestCount); got < 2 {
		t.Fatalf("expected JWKS refetch after cache expiry, got %d fetches", got)
	}
}

func TestJWTAuthPolicy_Security_AlgNoneRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createUnsignedNoneToken(t, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Security_ValidateIssuerTrue_RejectsUnknownIssuer(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://unknown.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["validateIssuer"] = true

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Security_ValidateIssuerFalse_AllowsIssuerMismatch_WithValidSignature(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://unknown.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["validateIssuer"] = false

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Security_UserIssuers_MultipleManagers_TriesFallbackManager(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	goodPrivateKey, goodPublicKey := generateTestKeys(t)
	_, badPublicKey := generateTestKeys(t)

	token := createRS256TokenWithKid(t, goodPrivateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	}, "test-kid")

	params := newRemoteParams("http://unused/jwks.json")
	params["keyManagers"] = []interface{}{
		map[string]interface{}{
			"name": "km-bad",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, badPublicKey),
				},
			},
		},
		map[string]interface{}{
			"name": "km-good",
			"jwks": map[string]interface{}{
				"local": map[string]interface{}{
					"inline": publicKeyToPEM(t, goodPublicKey),
				},
			},
		},
	}
	params["issuers"] = []interface{}{"km-bad", "km-good"}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Security_MissingIss_ValidateIssuerToggle(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub": "user-123",
	}, "test-kid")

	tests := []struct {
		name       string
		validate   bool
		expectPass bool
		statusCode int
	}{
		{name: "validateIssuer_true_rejects", validate: true, expectPass: false, statusCode: 401},
		{name: "validateIssuer_false_allows", validate: false, expectPass: true, statusCode: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			params := newRemoteParams(jwksServer.URL + "/jwks.json")
			params["validateIssuer"] = tc.validate

			ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
			if tc.expectPass {
				assertAuthSuccess(t, ctx, action)
			} else {
				assertAuthFailure(t, ctx, action, tc.statusCode)
			}
		})
	}
}

func TestJWTAuthPolicy_Security_AuthorizationSchemeCaseInsensitive(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createTestToken(t, privateKey, map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "bearer", token))
	assertAuthSuccess(t, ctx, action)
}

func TestJWTAuthPolicy_Regression_ErrorFormats_JsonPlainMinimal(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	tests := []struct {
		name           string
		format         string
		expectedType   string
		expectBodyText string
		expectEmpty    bool
	}{
		{
			name:         "json",
			format:       "json",
			expectedType: "application/json",
		},
		{
			name:           "plain",
			format:         "plain",
			expectedType:   "text/plain",
			expectBodyText: "custom error message",
		},
		{
			name:           "minimal",
			format:         "minimal",
			expectedType:   "application/json",
			expectBodyText: "Unauthorized",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetJWTAuthSingletonCache(t)

			params := newRemoteParams("http://localhost:8080/jwks.json")
			params["errorMessageFormat"] = tc.format
			params["errorMessage"] = "custom error message"
			params["onFailureStatusCode"] = 401

			ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
			assertAuthFailure(t, ctx, action, 401)

			resp := action.(policy.ImmediateResponse)
			if resp.Headers["content-type"] != tc.expectedType {
				t.Fatalf("expected content-type %s, got %s", tc.expectedType, resp.Headers["content-type"])
			}

			if tc.expectBodyText != "" && string(resp.Body) != tc.expectBodyText {
				t.Fatalf("expected body %q, got %q", tc.expectBodyText, string(resp.Body))
			}

			if tc.expectEmpty && len(resp.Body) != 0 {
				t.Fatalf("expected empty response body, got %q", string(resp.Body))
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_OnFailureStatusCodeHonored(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	params := newRemoteParams("http://localhost:8080/jwks.json")
	params["onFailureStatusCode"] = 403
	ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
	assertAuthFailure(t, ctx, action, 403)
}

func TestJWTAuthPolicy_Regression_MetadataSetOnSuccessAndFailure(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	t.Run("success_metadata", func(t *testing.T) {
		resetJWTAuthSingletonCache(t)

		privateKey, publicKey := generateTestKeys(t)
		jwksServer := createJWKSServer(t, publicKey, "test-kid")
		defer jwksServer.Close()

		token := createTestToken(t, privateKey, map[string]interface{}{
			"sub": "user-123",
			"iss": "https://issuer.example.com",
		})
		params := newRemoteParams(jwksServer.URL + "/jwks.json")

		ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
		assertAuthSuccess(t, ctx, action)

		if ctx.SharedContext.AuthContext == nil || ctx.SharedContext.AuthContext.AuthType != "jwt" {
			t.Fatalf("expected auth type to be jwt")
		}
	})

	t.Run("failure_metadata", func(t *testing.T) {
		resetJWTAuthSingletonCache(t)

		params := newRemoteParams("http://localhost:8080/jwks.json")
		ctx, action := executeOnRequestHeaders(t, params, map[string][]string{})
		assertAuthFailure(t, ctx, action, 401)

		// On failure, AuthContext should indicate not authenticated
		if ctx.SharedContext.AuthContext != nil && ctx.SharedContext.AuthContext.Authenticated {
			t.Fatalf("did not expect authenticated context on failure path")
		}
	})
}

func TestJWTAuthPolicy_Regression_ModeContract(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	p := mustGetPolicy(t, map[string]interface{}{})
	jwtPolicy, ok := p.(*JwtAuthPolicy)
	if !ok {
		t.Fatalf("expected *JwtAuthPolicy, got %T", p)
	}

	mode := jwtPolicy.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Fatalf("expected RequestHeaderMode to be process")
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Fatalf("expected RequestBodyMode to be skip")
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Fatalf("expected ResponseHeaderMode to be skip")
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Fatalf("expected ResponseBodyMode to be skip")
	}
}

func TestJWTAuthPolicy_Regression_RequiredClaimsTypeMismatch(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createRS256TokenWithKid(t, privateKey, map[string]interface{}{
		"sub":  "user-123",
		"iss":  "https://issuer.example.com",
		"role": []interface{}{"admin"},
	}, "test-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	params["requiredClaims"] = map[string]interface{}{
		"role": "admin",
	}

	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

func TestJWTAuthPolicy_Regression_extractTokenVariants(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		scheme   string
		expected string
	}{
		{
			name:     "scheme_match",
			header:   "Bearer abc.def.ghi",
			scheme:   "Bearer",
			expected: "abc.def.ghi",
		},
		{
			name:     "raw_token_without_scheme",
			header:   "abc.def.ghi",
			scheme:   "",
			expected: "abc.def.ghi",
		},
		{
			name:     "strip_unknown_scheme_when_not_enforced",
			header:   "JWT abc.def.ghi",
			scheme:   "",
			expected: "abc.def.ghi",
		},
		{
			name:     "scheme_case_insensitive_match",
			header:   "bearer abc.def.ghi",
			scheme:   "Bearer",
			expected: "abc.def.ghi",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractToken(tc.header, tc.scheme)
			if got != tc.expected {
				t.Fatalf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_parseAudienceVariants(t *testing.T) {
	tests := []struct {
		name     string
		claim    interface{}
		expected []string
	}{
		{name: "single_string", claim: "a1", expected: []string{"a1"}},
		{name: "array_values", claim: []interface{}{"a1", "a2"}, expected: []string{"a1", "a2"}},
		{name: "mixed_array", claim: []interface{}{"a1", 123}, expected: []string{"a1"}},
		{name: "invalid_type", claim: 123, expected: []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAudience(tc.claim)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected %v, got %v", tc.expected, got)
				}
			}
		})
	}
}

func TestJWTAuthPolicy_Regression_claimValueToStringAndGetKeyIds(t *testing.T) {
	if got := claimValueToString(float64(42)); got != "42" {
		t.Fatalf("expected numeric conversion, got %q", got)
	}
	if got := claimValueToString(true); got != "true" {
		t.Fatalf("expected bool conversion, got %q", got)
	}
	if got := claimValueToString([]interface{}{"a", "b"}); got != `["a","b"]` {
		t.Fatalf("expected json conversion for array, got %q", got)
	}

	key1 := &rsa.PublicKey{N: rsa.PublicKey{}.N, E: 65537}
	key2 := &rsa.PublicKey{N: rsa.PublicKey{}.N, E: 65537}
	keys := map[string]crypto.PublicKey{
		"kid-1": key1,
		"kid-2": key2,
	}
	ids := getKeyIds(keys)
	if len(ids) != 2 {
		t.Fatalf("expected 2 key IDs, got %d", len(ids))
	}
}

func resetJWTAuthSingletonCache(t *testing.T) {
	t.Helper()

	ins.cacheMutex.Lock()
	ins.cacheStore = make(map[string]*CachedJWKS)
	ins.cacheTTLs = make(map[string]time.Time)
	ins.cacheMutex.Unlock()

	t.Cleanup(func() {
		ins.cacheMutex.Lock()
		ins.cacheStore = make(map[string]*CachedJWKS)
		ins.cacheTTLs = make(map[string]time.Time)
		ins.cacheMutex.Unlock()
	})
}

func executeOnRequestHeaders(t *testing.T, params map[string]interface{}, headers map[string][]string) (*policy.RequestHeaderContext, policy.RequestHeaderAction) {
	t.Helper()
	p := mustGetPolicy(t, params)
	ctx := createMockRequestHeaderContext(headers)
	return ctx, p.(*JwtAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)
}

func mustGetPolicy(t *testing.T, params map[string]interface{}) policy.Policy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy failed: %v", err)
	}
	return p
}

func newRemoteParams(jwksURI string) map[string]interface{} {
	return map[string]interface{}{
		"headerName":             "Authorization",
		"authHeaderScheme":       "Bearer",
		"onFailureStatusCode":    401,
		"errorMessageFormat":     "json",
		"errorMessage":           "Authentication failed",
		"leeway":                 "30s",
		"jwksCacheTtl":           "5m",
		"jwksFetchTimeout":       "100ms",
		"jwksFetchRetryCount":    0,
		"jwksFetchRetryInterval": "1ms",
		"validateIssuer":         true,
		"keyManagers": []interface{}{
			map[string]interface{}{
				"name":   "km-primary",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"remote": map[string]interface{}{
						"uri": jwksURI,
					},
				},
			},
		},
	}
}

func authHeader(headerName, scheme, token string) map[string][]string {
	header := strings.ToLower(headerName)
	return map[string][]string{
		header: {fmt.Sprintf("%s %s", scheme, token)},
	}
}

func assertAuthSuccess(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction) {
	t.Helper()

	if reqCtx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if reqCtx.SharedContext.AuthContext == nil || !reqCtx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected auth success, got unauthenticated context")
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
}

func assertAuthFailure(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction, statusCode int) {
	t.Helper()

	if reqCtx == nil {
		t.Fatalf("request context cannot be nil")
	}
	if reqCtx.SharedContext.AuthContext != nil && reqCtx.SharedContext.AuthContext.Authenticated {
		t.Fatalf("expected auth failure, got authenticated context")
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != statusCode {
		t.Fatalf("expected status code %d, got %d", statusCode, resp.StatusCode)
	}
}

func createRS256TokenWithKid(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

func createUnsignedNoneToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	claims = normalizeClaims(claims)

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))

	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create unsigned token: %v", err)
	}
	return tokenString
}

func createTokenWithoutAlgHeader(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)

	headerJSON, err := json.Marshal(map[string]string{"typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := header + "." + payload

	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func normalizeClaims(claims map[string]interface{}) map[string]interface{} {
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	return claims
}

// TestJWTAuthPolicy_Security_HMACConfusionRejected verifies that HS256 tokens are rejected
// because HS256 is not in the hardcoded supported algorithm set.
func TestJWTAuthPolicy_Security_HMACConfusionRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	_, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	pubDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(pubDER)
	if err != nil {
		t.Fatalf("failed to sign HS256 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Security_PS256Accepted verifies that PS256 (RSASSA-PSS) tokens are accepted
// when the JWKS contains the corresponding RSA public key.
func TestJWTAuthPolicy_Security_PS256Accepted(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign PS256 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthSuccess(t, ctx, action)
}

// generateTestECKeys generates a P-256 ECDSA key pair for testing.
func generateTestECKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// createECJWKSServer creates a test HTTP server that serves a JWKS with a P-256 EC public key.
func createECJWKSServer(t *testing.T, publicKey *ecdsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		xB64 := base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes())
		yB64 := base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes())
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "EC",
					"kid": kid,
					"use": "sig",
					"alg": "ES256",
					"crv": "P-256",
					"x":   xB64,
					"y":   yB64,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Logf("failed to encode EC JWKS: %v", err)
		}
	}))
	return server
}

// createES256Token mints an ES256 JWT signed with the given EC private key.
func createES256Token(t *testing.T, privateKey *ecdsa.PrivateKey, claims map[string]interface{}, kid string) string {
	t.Helper()
	claims = normalizeClaims(claims)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign ES256 token: %v", err)
	}
	return tokenString
}

// TestJWTAuthPolicy_Security_ES256Accepted verifies end-to-end ES256 support:
// the JWKS parser stores an EC key, the Keyfunc binds it to ECDSA, and the token passes.
func TestJWTAuthPolicy_Security_ES256Accepted(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	ecPriv, ecPub := generateTestECKeys(t)
	jwksServer := createECJWKSServer(t, ecPub, "ec-kid")
	defer jwksServer.Close()

	token := createES256Token(t, ecPriv, map[string]interface{}{
		"sub": "user-456",
		"iss": "https://issuer.example.com",
	}, "ec-kid")

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthSuccess(t, ctx, action)
}

// TestJWTAuthPolicy_Security_ES256WithRSAKeyRejected verifies that an ES256 token is rejected
// when the JWKS only contains an RSA key — the Keyfunc must refuse the method/key-type mismatch.
func TestJWTAuthPolicy_Security_ES256WithRSAKeyRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	// RSA JWKS
	_, rsaPub := generateTestKeys(t)
	rsaJWKSServer := createJWKSServer(t, rsaPub, "rsa-kid")
	defer rsaJWKSServer.Close()

	// EC private key — token claims ES256 but JWKS has RSA
	ecPriv, _ := generateTestECKeys(t)
	token := createES256Token(t, ecPriv, map[string]interface{}{
		"sub": "user-789",
		"iss": "https://issuer.example.com",
	}, "rsa-kid") // deliberately uses the RSA kid so key lookup succeeds, Keyfunc must then reject

	params := newRemoteParams(rsaJWKSServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", token))
	assertAuthFailure(t, ctx, action, 401)
}

// TestJWTAuthPolicy_Security_UnsupportedAlgRejected verifies that algorithms outside the fixed
// set (RS256, PS256, ES256) are rejected by WithValidMethods before the Keyfunc is reached.
// RS384 is used: the JWKS key material matches the token's key, so the only reason for
// rejection is that RS384 is not in supportedAlgorithms.
func TestJWTAuthPolicy_Security_UnsupportedAlgRejected(t *testing.T) {
	resetJWTAuthSingletonCache(t)

	privateKey, publicKey := generateTestKeys(t)
	jwksServer := createJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	claims := normalizeClaims(map[string]interface{}{
		"sub": "user-123",
		"iss": "https://issuer.example.com",
	})
	tok := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims(claims))
	tok.Header["kid"] = "test-kid"
	tokenString, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign RS384 token: %v", err)
	}

	params := newRemoteParams(jwksServer.URL + "/jwks.json")
	ctx, action := executeOnRequestHeaders(t, params, authHeader("Authorization", "Bearer", tokenString))
	assertAuthFailure(t, ctx, action, 401)
}

func writeJWKSResponse(t *testing.T, w http.ResponseWriter, publicKey *rsa.PublicKey, kid string) {
	t.Helper()
	nBytes := publicKey.N.Bytes()
	nB64 := base64.RawURLEncoding.EncodeToString(nBytes)

	eBytes := make([]byte, 4)
	eBytes[0] = byte((publicKey.E >> 24) & 0xFF)
	eBytes[1] = byte((publicKey.E >> 16) & 0xFF)
	eBytes[2] = byte((publicKey.E >> 8) & 0xFF)
	eBytes[3] = byte(publicKey.E & 0xFF)
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   nB64,
				"e":   eB64,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		t.Logf("Failed to encode JWKS: %v", err)
	}
}

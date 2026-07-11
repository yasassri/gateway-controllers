/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package mcpauthn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestMcpAuthPolicy_Mode(t *testing.T) {
	p := &McpAuthPolicy{}
	got := p.Mode()
	want := policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
	if got != want {
		t.Fatalf("unexpected mode: got %+v, want %+v", got, want)
	}
}

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Errorf("GetPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("GetPolicy returned nil policy")
	}
}

func TestOnRequestHeaders_WellKnown_Success(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"requiredScopes": []any{"scope1", "scope2"},
	})
	ctx := createMockRequestHeaderContext(map[string][]string{
		McpSessionHeader: {"session-123"},
	})
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Headers[McpSessionHeader] != "session-123" {
		t.Errorf("Expected session header 'session-123', got %s", resp.Headers[McpSessionHeader])
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	expectedResource := "http://localhost:8080/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}

	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://issuer1.com" {
		t.Errorf("Unexpected authorization servers: %v", metadata.AuthorizationServers)
	}

	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("Unexpected scopes supported: %v", metadata.ScopesSupported)
	}
}

func TestOnRequestHeaders_WellKnown_NoKeyManagers(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_NoKeyManagers_WithForbiddenStatus(t *testing.T) {
	p := &McpAuthPolicy{
		OnFailureStatusCode: 403,
		ErrorMessageFormat:  "json",
	}
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_FilteredIssuers(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"issuers": []any{"km2"}, // Only allow km2
	})
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
			map[string]any{
				"name":   "km2",
				"issuer": "https://issuer2.com",
			},
		},
	}

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://issuer2.com" {
		t.Errorf("Expected only issuer2, got %v", metadata.AuthorizationServers)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(map[string][]string{
		McpSessionHeader: {"session-456"},
	})
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "localhost:8443"
	ctx.Vhost = "api.example.com"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should use vhost (api.example.com) with port from authority (8443)
	expectedResource := "https://api.example.com:8443/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost_StandardPort(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "api.example.com:443"
	ctx.Vhost = "api.example.com"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should use vhost without port since 443 is standard for https
	expectedResource := "https://api.example.com/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestHeaders_WellKnown_WithVhost_AndAPIContext(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"
	ctx.Scheme = "https"
	ctx.Authority = "localhost:8443"
	ctx.Vhost = "api.example.com"
	ctx.APIContext = "/v1/myapi"

	params := map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	}

	action := p.OnRequestHeaders(context.Background(), ctx, params)

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}

	var metadata ProtectedResourceMetadata
	if err := json.Unmarshal(resp.Body, &metadata); err != nil {
		t.Fatalf("Failed to unmarshal body: %v", err)
	}

	// Should include API context in the resource path
	expectedResource := "https://api.example.com:8443/v1/myapi/mcp"
	if metadata.Resource != expectedResource {
		t.Errorf("Expected resource '%s', got '%s'", expectedResource, metadata.Resource)
	}
}

func TestOnRequestBody_Delegation_Failure(t *testing.T) {
	_, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	p := createTestPolicy()
	ctx := createMockRequestBodyContext(map[string][]string{
		McpSessionHeader: {"session-123"},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	// Pass keyManagers but no valid JWT token - JWT Auth should fail with 401
	params := map[string]any{
		"gatewayHost": "gateway.com",
		"keyManagers": []any{
			map[string]any{
				"name":   "test-km",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// We expect ImmediateResponse (failure from JWT Auth wrapped)
	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse (auth failure), got %T", action)
	}

	if resp.StatusCode != 401 {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	authHeader := resp.Headers[WWWAuthenticateHeader]
	if authHeader == "" {
		t.Error("Expected WWW-Authenticate header")
	}

	expectedPrefix := `Bearer resource_metadata="http://gateway.com:8080/.well-known/oauth-protected-resource"`
	if !strings.HasPrefix(authHeader, expectedPrefix) {
		t.Errorf("Unexpected WWW-Authenticate header: %s", authHeader)
	}

	if resp.Headers[McpSessionHeader] != "session-123" {
		t.Errorf("Expected session header 'session-123', got %s", resp.Headers[McpSessionHeader])
	}
}

func TestOnRequestBody_InvalidOnFailureStatusCode(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Path = "/api/resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"onFailureStatusCode": 200,
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestBody_InvalidErrorMessageFormat(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Path = "/api/resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"errorMessageFormat": "xml",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_PathWithPrefix_Success(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/mcp/v1/.well-known/oauth-protected-resource"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_WellKnown_FalsePositivePathDoesNotMatch(t *testing.T) {
	p := createTestPolicy()
	ctx := createMockRequestHeaderContext(nil)
	ctx.Method = "GET"
	ctx.OperationPath = "/api/.well-known/oauth-protected-resource-extra"

	action := p.OnRequestHeaders(context.Background(), ctx, map[string]any{})

	// The path doesn't match well-known endpoint pattern
	// so the policy returns UpstreamRequestHeaderModifications (no action taken)
	_, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("Expected UpstreamRequestHeaderModifications (no match), got %T", action)
	}
}

func TestOnRequestBody_WellKnown_MissingIssuerInKeyManagerConfig(t *testing.T) {
	p := &McpAuthPolicy{}
	ctx := createMockRequestBodyContext(nil)
	ctx.Method = "GET"
	ctx.Path = "/.well-known/oauth-protected-resource"

	action := p.OnRequestBody(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name": "km1",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("Expected status 500, got %d", resp.StatusCode)
	}
}

func TestOnRequestHeaders_HandleAuthFailureWithNilMetadata(t *testing.T) {
	p, _ := GetPolicy(policy.PolicyMetadata{}, map[string]any{
		"issuers": []any{"unknown-km"},
	})
	ctx := createMockRequestHeaderContext(nil)
	ctx.SharedContext.Metadata = nil
	ctx.Method = "GET"
	ctx.OperationPath = "/.well-known/oauth-protected-resource"

	action := p.(*McpAuthPolicy).OnRequestHeaders(context.Background(), ctx, map[string]any{
		"keyManagers": []any{
			map[string]any{
				"name":   "km1",
				"issuer": "https://issuer1.com",
			},
		},
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("Expected ImmediateResponse, got %T", action)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("Expected status 401, got %d", resp.StatusCode)
	}
	if ctx.SharedContext.Metadata == nil {
		t.Fatal("Expected metadata map to be initialized")
	}
	if got := ctx.SharedContext.Metadata[MetadataKeyAuthSuccess]; got != false {
		t.Fatalf("Expected auth.success=false, got %v", got)
	}
	if got := ctx.SharedContext.Metadata[MetadataKeyAuthMethod]; got != "mcpAuth" {
		t.Fatalf("Expected auth.method=mcpAuth, got %v", got)
	}
}

// createTestPolicy creates an McpAuthPolicy with valid default configuration for testing
func createTestPolicy() *McpAuthPolicy {
	return &McpAuthPolicy{
		OnFailureStatusCode: 401,
		ErrorMessageFormat:  "json",
		AuthConfig:          GetMcpAuthConfig(map[string]any{}),
	}
}

func TestOnRequestBody_Delegation_Success_SetsAuthContextAuthType(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	token := createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"scope": "read write",
	})

	p := createTestPolicy()
	ctx := createMockRequestBodyContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	params := map[string]any{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"allowedAlgorithms":   []any{"RS256"},
		"keyManagers": []any{
			map[string]any{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// Should NOT be an ImmediateResponse — jwt-auth succeeded
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("Expected successful action (not ImmediateResponse), but got auth failure")
	}

	// AuthContext must be set and authenticated
	if ctx.SharedContext.AuthContext == nil {
		t.Fatal("Expected AuthContext to be set on success")
	}
	if !ctx.SharedContext.AuthContext.Authenticated {
		t.Error("Expected AuthContext.Authenticated=true on success")
	}
	// AuthType must be overridden to mcp/oauth by mcp-auth
	if ctx.SharedContext.AuthContext.AuthType != "mcp/oauth" {
		t.Errorf("Expected AuthType='mcp/oauth', got %q", ctx.SharedContext.AuthContext.AuthType)
	}
}

// TestOnRequestBody_RequiredScopes_NotEnforced: requiredScopes are advertise-only, so a token missing them still authenticates. Regression test for wso2/api-platform#2589.
func TestOnRequestBody_RequiredScopes_NotEnforced(t *testing.T) {
	privateKey, publicKey := generateRSATestKeys(t)
	jwksServer := createMcpTestJWKSServer(t, publicKey, "test-kid")
	defer jwksServer.Close()

	// Token carries only "read" — missing "write" and "admin".
	token := createMcpTestToken(t, privateKey, map[string]interface{}{
		"sub":   "user123",
		"iss":   "https://issuer.example.com",
		"scope": "read",
	})

	p := createTestPolicy()
	p.RequiredScopes = []string{"read", "write", "admin"}

	ctx := createMockRequestBodyContext(map[string][]string{
		"authorization": {fmt.Sprintf("Bearer %s", token)},
	})
	ctx.Method = "POST"
	ctx.Path = "/mcp"
	ctx.OperationPath = "/mcp"

	params := map[string]any{
		"headerName":          "Authorization",
		"authHeaderScheme":    "Bearer",
		"onFailureStatusCode": 401,
		"errorMessageFormat":  "json",
		"allowedAlgorithms":   []any{"RS256"},
		// Present in params as at runtime; the policy must strip it before delegating.
		"requiredScopes": []any{"read", "write", "admin"},
		"keyManagers": []any{
			map[string]any{
				"name":   "test-issuer",
				"issuer": "https://issuer.example.com",
				"jwks": map[string]any{
					"remote": map[string]any{
						"uri": jwksServer.URL + "/jwks.json",
					},
				},
			},
		},
	}

	action := p.OnRequestBody(context.Background(), ctx, params)

	// Must NOT be rejected: requiredScopes are advertised, not enforced, by mcp-auth.
	if _, ok := action.(policy.ImmediateResponse); ok {
		t.Fatalf("Expected success despite missing scopes (advertise-only), but got auth failure")
	}
	if ctx.SharedContext.AuthContext == nil || !ctx.SharedContext.AuthContext.Authenticated {
		t.Fatal("Expected token to authenticate successfully even though it lacks configured requiredScopes")
	}

	// The original params map must be left untouched (no in-place deletion).
	if _, ok := params["requiredScopes"]; !ok {
		t.Error("Expected params[\"requiredScopes\"] to be preserved; policy must copy, not mutate")
	}
}

func createMockRequestBodyContext(headers map[string][]string) *policy.RequestContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers:   policy.NewHeaders(headers),
		Path:      "/api/test",
		Method:    "GET",
		Scheme:    "http",
		Authority: "localhost:8080",
	}
}

// createMockRequestHeaderContext creates a RequestHeaderContext for testing OnRequestHeaders
func createMockRequestHeaderContext(headers map[string][]string) *policy.RequestHeaderContext {
	if headers == nil {
		headers = map[string][]string{}
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "test-request-id",
			Metadata:  make(map[string]any),
		},
		Headers:   policy.NewHeaders(headers),
		Path:      "/api/test",
		Method:    "GET",
		Scheme:    "http",
		Authority: "localhost:8080",
	}
}

// generateRSATestKeys creates a fresh RSA key pair for use in tests.
func generateRSATestKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// createMcpTestToken creates a signed JWT with the given claims, valid for 1 hour.
func createMcpTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]interface{}) string {
	t.Helper()
	mapClaims := jwt.MapClaims{}
	for k, v := range claims {
		mapClaims[k] = v
	}
	mapClaims["exp"] = time.Now().Add(time.Hour).Unix()
	mapClaims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return signed
}

// createMcpTestJWKSServer starts an httptest server that serves a JWKS for the given public key.
func createMcpTestJWKSServer(t *testing.T, publicKey *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(nBytes),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Failed to marshal JWKS: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksJSON)
	}))
}

func TestGetSecurityConfigParam_Defaults(t *testing.T) {
	params := map[string]interface{}{}

	config := getSecurityConfigParam(params, "tools")

	if !config.Enabled {
		t.Error("Expected Enabled to default to true")
	}
	if len(config.Exceptions) != 0 {
		t.Errorf("Expected empty exceptions, got %v", config.Exceptions)
	}
}

func TestGetSecurityConfigParam_WithValues(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"tool1", "tool2"},
		},
	}

	config := getSecurityConfigParam(params, "tools")

	if config.Enabled {
		t.Error("Expected Enabled to be false")
	}
	if len(config.Exceptions) != 2 {
		t.Errorf("Expected 2 exceptions, got %d", len(config.Exceptions))
	}
	if config.Exceptions[0] != "tool1" || config.Exceptions[1] != "tool2" {
		t.Errorf("Unexpected exceptions: %v", config.Exceptions)
	}
}

func TestGetMcpAuthConfig_AllFields(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{"public-tool"},
		},
		"resources": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"public-resource"},
		},
		"prompts": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{},
		},
		"methods": map[string]interface{}{
			"enabled":    false,
			"exceptions": []interface{}{"initialize", "ping"},
		},
	}

	config := GetMcpAuthConfig(params)

	// Check tools
	if !config.Tools.Enabled {
		t.Error("Expected Tools.Enabled to be true")
	}
	if len(config.Tools.Exceptions) != 1 || config.Tools.Exceptions[0] != "public-tool" {
		t.Errorf("Unexpected Tools.Exceptions: %v", config.Tools.Exceptions)
	}

	// Check resources
	if config.Resources.Enabled {
		t.Error("Expected Resources.Enabled to be false")
	}
	if len(config.Resources.Exceptions) != 1 || config.Resources.Exceptions[0] != "public-resource" {
		t.Errorf("Unexpected Resources.Exceptions: %v", config.Resources.Exceptions)
	}

	// Check prompts
	if !config.Prompts.Enabled {
		t.Error("Expected Prompts.Enabled to be true")
	}
	if len(config.Prompts.Exceptions) != 0 {
		t.Errorf("Expected empty Prompts.Exceptions, got %v", config.Prompts.Exceptions)
	}

	// Check methods
	if config.Methods.Enabled {
		t.Error("Expected Methods.Enabled to be false")
	}
	if len(config.Methods.Exceptions) != 2 {
		t.Errorf("Expected 2 Methods.Exceptions, got %d", len(config.Methods.Exceptions))
	}
}

func TestGetMcpAuthConfig_EmptyParams(t *testing.T) {
	params := map[string]interface{}{}

	config := GetMcpAuthConfig(params)

	// All should have defaults
	if !config.Tools.Enabled || !config.Resources.Enabled || !config.Prompts.Enabled || !config.Methods.Enabled {
		t.Error("Expected all security configs to default to enabled=true")
	}
}

func TestGetMcpAuthPolicy_WithIssuersAndScopes(t *testing.T) {
	params := map[string]interface{}{
		"tools": map[string]interface{}{
			"enabled":    true,
			"exceptions": []interface{}{"public-tool"},
		},
		"issuers":        []interface{}{"issuer1", "issuer2"},
		"requiredScopes": []interface{}{"read", "write"},
	}

	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}

	mcpPolicy := p.(*McpAuthPolicy)

	// Check issuers
	if len(mcpPolicy.Issuers) != 2 {
		t.Errorf("Expected 2 issuers, got %d", len(mcpPolicy.Issuers))
	}

	// Check scopes
	if len(mcpPolicy.RequiredScopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(mcpPolicy.RequiredScopes))
	}

	// Check that AuthConfig was also set
	if !mcpPolicy.AuthConfig.Tools.Enabled {
		t.Error("Expected AuthConfig.Tools.Enabled to be true")
	}
}

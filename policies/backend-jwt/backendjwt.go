/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package backendjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultHeader      = "x-jwt-assertion"
	defaultTokenExpiry = 15 * time.Minute
	defaultAlgorithm   = "SHA256withRSA"
	minCacheTTL        = 30 * time.Second
)

// cachedToken holds a signed JWT string and its cache expiry time.
type cachedToken struct {
	signed    string
	expiresAt time.Time
}

// resolvedClaims holds the extra claims derived from claimMappings and customClaims
// in a single pass, split by type so cache-key and JWT population can share the work.
type resolvedClaims struct {
	// stringClaims: claimMappings results + resolved string customClaims (including $ctx:).
	stringClaims map[string]string
	// rawClaims: non-string customClaims (numbers, booleans) preserved as-is for JWT.
	rawClaims map[string]interface{}
}

// BackendJWTPolicy generates a signed JWT from the authenticated user context
// and injects it into the upstream request header. It is designed to run after
// an authentication policy (e.g. jwt-auth, basic-auth, api-key-auth).
type BackendJWTPolicy struct {
	keyMu    sync.RWMutex
	keyCache map[[32]byte]crypto.PrivateKey

	tokenMu    sync.RWMutex
	tokenCache map[string]cachedToken
}

// algorithmEntry describes a supported JWT signing algorithm.
// To add a new algorithm: add a single entry to the algorithms map below.
type algorithmEntry struct {
	method  jwt.SigningMethod
	keyType string // "rsa", "ecdsa", or "none"
}

// algorithms is the single source of truth for supported signing algorithms.
var algorithms = map[string]algorithmEntry{
	"SHA256withRSA": {jwt.SigningMethodRS256, "rsa"},
	"ES256":         {jwt.SigningMethodES256, "ecdsa"},
	"NONE":          {jwt.SigningMethodNone, "none"},
}

var ins = &BackendJWTPolicy{
	keyCache:   make(map[[32]byte]crypto.PrivateKey),
	tokenCache: make(map[string]cachedToken),
}

var startCleanup sync.Once

func startCacheCleanupOnce() {
	startCleanup.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				ins.evictExpired()
			}
		}()
	})
}

func (p *BackendJWTPolicy) evictExpired() {
	now := time.Now()
	p.tokenMu.Lock()
	for k, v := range p.tokenCache {
		if now.After(v.expiresAt) {
			delete(p.tokenCache, k)
		}
	}
	p.tokenMu.Unlock()
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	startCacheCleanupOnce()
	return ins, nil
}

func (p *BackendJWTPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// Validate checks the algorithm is supported and, for key-based algorithms,
// that the signing key is present and parseable at config load time.
func (p *BackendJWTPolicy) Validate(params map[string]interface{}) error {
	alg := getString(params, "algorithm", defaultAlgorithm)
	entry, ok := algorithms[alg]
	if !ok {
		return fmt.Errorf("unsupported algorithm %q; supported: %s", alg, algorithmList())
	}
	if entry.keyType == "none" {
		return nil
	}
	pemBytes, err := extractSigningKeyPEM(params)
	if err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	key, err := parsePrivateKey(pemBytes)
	if err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	return checkKeyType(key, entry.keyType, alg)
}

// OnRequestHeaders generates a signed JWT from the auth context and sets it on the upstream request.
func (p *BackendJWTPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	requireAuth := getBool(params, "requireAuthentication", false)
	authCtx := reqCtx.SharedContext.AuthContext

	if authCtx == nil || !authCtx.Authenticated {
		if requireAuth {
			slog.Debug("Backend JWT: no authenticated context, rejecting request")
			return policy.ImmediateResponse{
				StatusCode: 401,
				Headers:    map[string]string{"content-type": "application/json"},
				Body:       []byte(`{"error":"Unauthorized","message":"Authentication is required to generate a backend JWT"}`),
			}
		}
		slog.Debug("Backend JWT: no authenticated context, passing through")
		return policy.UpstreamRequestHeaderModifications{}
	}

	alg := getString(params, "algorithm", defaultAlgorithm)
	entry, ok := algorithms[alg]
	if !ok {
		slog.Error("Backend JWT: unsupported algorithm", "algorithm", alg)
		return internalError()
	}
	issuer := getString(params, "issuer", "")
	expiry := parseDuration(getString(params, "tokenExpiry", ""), defaultTokenExpiry)
	headerName := getString(params, "header", defaultHeader)

	// Resolve extra claims once — used for both the cache key and JWT population.
	extras := resolveExtraClaims(authCtx, reqCtx, params)

	cacheKey := buildTokenCacheKey(
		authCtx.CredentialID, authCtx.Subject, reqCtx.APIContext, reqCtx.APIVersion,
		authCtx.Audience, extras,
	)
	if signed, ok := p.getCachedToken(cacheKey); ok {
		slog.Debug("Backend JWT: cache hit", "subject", authCtx.Subject)
		return policy.UpstreamRequestHeaderModifications{
			HeadersToSet: map[string]string{headerName: signed},
		}
	}

	signingMethod := entry.method
	var signKey interface{}
	if entry.keyType == "none" {
		signKey = jwt.UnsafeAllowNoneSignatureType
	} else {
		pemBytes, err := extractSigningKeyPEM(params)
		if err != nil {
			slog.Error("Backend JWT: failed to extract signing key", "error", err)
			return internalError()
		}
		key, err := p.loadKey(pemBytes)
		if err != nil {
			slog.Error("Backend JWT: failed to parse signing key", "error", err)
			return internalError()
		}
		if err := checkKeyType(key, entry.keyType, alg); err != nil {
			slog.Error("Backend JWT: key type mismatch", "algorithm", alg, "error", err)
			return internalError()
		}
		signKey = key
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat":       now.Unix(),
		"exp":       now.Add(expiry).Unix(),
		"sub":       authCtx.Subject,
		"auth_type": authCtx.AuthType,
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	if authCtx.Issuer != "" {
		claims["original_iss"] = authCtx.Issuer
	}
	if len(authCtx.Audience) > 0 {
		claims["aud"] = authCtx.Audience
	}
	if authCtx.CredentialID != "" {
		claims["credential_id"] = authCtx.CredentialID
	}
	for k, v := range extras.stringClaims {
		claims[k] = v
	}
	for k, v := range extras.rawClaims {
		claims[k] = v
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	signed, err := token.SignedString(signKey)
	if err != nil {
		slog.Error("Backend JWT: failed to sign token", "error", err)
		return internalError()
	}

	p.putCachedToken(cacheKey, signed, expiry)
	slog.Debug("Backend JWT: generated token", "header", headerName, "subject", authCtx.Subject)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			headerName: signed,
		},
	}
}

// loadKey returns a cached private key, parsing and caching it on first use.
func (p *BackendJWTPolicy) loadKey(pemBytes []byte) (crypto.PrivateKey, error) {
	fingerprint := sha256.Sum256(pemBytes)

	p.keyMu.RLock()
	key, ok := p.keyCache[fingerprint]
	p.keyMu.RUnlock()
	if ok {
		return key, nil
	}

	parsed, err := parsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	p.keyMu.Lock()
	p.keyCache[fingerprint] = parsed
	p.keyMu.Unlock()

	return parsed, nil
}

// resolveExtraClaims resolves claimMappings and customClaims in a single pass.
// stringClaims holds claimMappings results and resolved string customClaims (including $ctx: refs).
// rawClaims holds non-string customClaims preserved as their original types for JWT population.
func resolveExtraClaims(authCtx *policy.AuthContext, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) resolvedClaims {
	result := resolvedClaims{
		stringClaims: make(map[string]string),
		rawClaims:    make(map[string]interface{}),
	}

	if mappingsRaw, ok := params["claimMappings"]; ok {
		if mappings, ok := mappingsRaw.(map[string]interface{}); ok {
			for propKey, claimNameRaw := range mappings {
				claimName, ok := claimNameRaw.(string)
				if !ok {
					continue
				}
				if val, ok := authCtx.Properties[propKey]; ok {
					result.stringClaims[claimName] = val
				}
			}
		}
	}

	if customRaw, ok := params["customClaims"]; ok {
		if custom, ok := customRaw.(map[string]interface{}); ok {
			for k, v := range custom {
				strVal, ok := v.(string)
				if !ok {
					result.rawClaims[k] = v
					continue
				}
				resolved, ok := resolveClaimValue(strVal, reqCtx)
				if !ok {
					slog.Debug("Backend JWT: skipping claim — context variable not resolvable",
						"claim", k, "ref", strVal)
					continue
				}
				result.stringClaims[k] = resolved
			}
		}
	}

	return result
}

// buildTokenCacheKey returns a hex SHA256 of the fields that determine what the generated JWT contains.
// audience and extra claims are sorted so the key is deterministic regardless of slice/map ordering.
func buildTokenCacheKey(credentialID, subject, apiContext, apiVersion string, audience []string, extras resolvedClaims) string {
	sortedAud := make([]string, len(audience))
	copy(sortedAud, audience)
	sort.Strings(sortedAud)

	allKeys := make([]string, 0, len(extras.stringClaims)+len(extras.rawClaims))
	for k := range extras.stringClaims {
		allKeys = append(allKeys, k)
	}
	for k := range extras.rawClaims {
		if _, exists := extras.stringClaims[k]; !exists {
			allKeys = append(allKeys, k)
		}
	}
	sort.Strings(allKeys)

	var sb strings.Builder
	sb.WriteString(credentialID)
	sb.WriteByte('|')
	sb.WriteString(subject)
	sb.WriteByte('|')
	sb.WriteString(apiContext)
	sb.WriteByte('|')
	sb.WriteString(apiVersion)
	sb.WriteByte('|')
	sb.WriteString(strings.Join(sortedAud, ","))
	for _, k := range allKeys {
		sb.WriteByte('|')
		sb.WriteString(k)
		sb.WriteByte('=')
		if v, ok := extras.stringClaims[k]; ok {
			sb.WriteString(v)
		} else {
			sb.WriteString(fmt.Sprintf("%v", extras.rawClaims[k]))
		}
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("%x", sum)
}

// getCachedToken returns a previously signed token if it exists and has not yet expired.
func (p *BackendJWTPolicy) getCachedToken(key string) (string, bool) {
	p.tokenMu.RLock()
	entry, ok := p.tokenCache[key]
	p.tokenMu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.signed, true
}

// putCachedToken stores a signed token in the cache with a TTL of half the token expiry,
// subject to a minimum of minCacheTTL. Using half the expiry avoids serving tokens that
// are about to expire while still providing a meaningful cache window.
func (p *BackendJWTPolicy) putCachedToken(key, signed string, tokenExpiry time.Duration) {
	ttl := tokenExpiry / 2
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	p.tokenMu.Lock()
	p.tokenCache[key] = cachedToken{
		signed:    signed,
		expiresAt: time.Now().Add(ttl),
	}
	p.tokenMu.Unlock()
}

// extractSigningKeyPEM reads PEM bytes from params["signingKey"].inline or params["signingKey"].path.
func extractSigningKeyPEM(params map[string]interface{}) ([]byte, error) {
	signingKeyRaw, ok := params["signingKey"]
	if !ok {
		return nil, fmt.Errorf("signingKey is required")
	}
	signingKeyMap, ok := signingKeyRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("signingKey must be an object with 'inline' or 'path'")
	}

	if inlineRaw, ok := signingKeyMap["inline"]; ok {
		inline, ok := inlineRaw.(string)
		if !ok || inline == "" {
			return nil, fmt.Errorf("signingKey.inline must be a non-empty string")
		}
		return []byte(inline), nil
	}

	if pathRaw, ok := signingKeyMap["path"]; ok {
		path, ok := pathRaw.(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("signingKey.path must be a non-empty string")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file %q: %w", path, err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("signingKey must specify either 'inline' or 'path'")
}

// parsePrivateKey decodes and parses a PEM-encoded RSA or ECDSA private key.
func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found in signing key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY", block.Type)
	}
}

// checkKeyType verifies that key matches the type required by the given algorithm.
func checkKeyType(key crypto.PrivateKey, keyType, algorithm string) error {
	switch keyType {
	case "rsa":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an RSA private key, got %T", algorithm, key)
		}
	case "ecdsa":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("%s requires an ECDSA private key, got %T", algorithm, key)
		}
	}
	return nil
}

// algorithmList returns a sorted, comma-separated list of supported algorithm names.
func algorithmList() string {
	names := make([]string, 0, len(algorithms))
	for k := range algorithms {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func getString(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return defaultVal
}

func getBool(params map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

const ctxPrefix = "$ctx:"

// resolveClaimValue returns the value to use for a custom JWT claim.
// Values prefixed with "$ctx:" are resolved from the request context at runtime.
// Returns ("", false) when a context variable cannot be resolved — the caller
// silently skips the claim rather than treating it as an error.
func resolveClaimValue(value string, reqCtx *policy.RequestHeaderContext) (string, bool) {
	if !strings.HasPrefix(value, ctxPrefix) {
		return value, true
	}
	variable := strings.ToLower(strings.TrimPrefix(value, ctxPrefix))

	switch {
	case variable == "request.path":
		return reqCtx.Path, true
	case variable == "request.method":
		return reqCtx.Method, true
	case variable == "request.authority":
		return reqCtx.Authority, true
	case variable == "request.scheme":
		return reqCtx.Scheme, true
	case strings.HasPrefix(variable, "request.header."):
		name := strings.TrimPrefix(variable, "request.header.")
		vals := reqCtx.Headers.Get(name)
		if len(vals) == 0 {
			return "", false
		}
		return vals[0], true
	case variable == "api.id":
		return reqCtx.APIId, true
	case variable == "api.name":
		return reqCtx.APIName, true
	case variable == "api.version":
		return reqCtx.APIVersion, true
	case variable == "api.context":
		return reqCtx.APIContext, true
	case variable == "auth.subject":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.Subject, true
	case variable == "auth.type":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.AuthType, true
	case variable == "auth.credential_id":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.CredentialID, true
	case strings.HasPrefix(variable, "auth.property."):
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		key := strings.TrimPrefix(variable, "auth.property.")
		val, ok := reqCtx.SharedContext.AuthContext.Properties[key]
		return val, ok
	default:
		return "", false
	}
}

func internalError() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"Internal Server Error"}`),
	}
}

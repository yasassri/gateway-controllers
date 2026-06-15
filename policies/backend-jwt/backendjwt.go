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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
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

// resolvedClaims holds the extra claims derived from customClaims, split by type
// so the cache key and JWT population can share the same resolved values.
type resolvedClaims struct {
	stringClaims map[string]string      // resolved string customClaims, including $ctx: refs
	rawClaims    map[string]interface{} // non-string customClaims (numbers, booleans) preserved as-is
}

// BackendJWTPolicy generates a signed JWT from the authenticated user context
// and injects it into the upstream request header. It is designed to run after
// an authentication policy (e.g. jwt-auth, basic-auth, api-key-auth).
type BackendJWTPolicy struct {
	keyMu    sync.RWMutex
	keyCache map[[32]byte]crypto.PrivateKey
	pemCache map[string][]byte // path → PEM bytes; avoids repeated file reads per cache miss

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
	pemCache:   make(map[string][]byte),
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
	pemBytes, err := p.extractSigningKeyPEM(params)
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
	authCtx := reqCtx.SharedContext.AuthContext

	alg := getString(params, "algorithm", defaultAlgorithm)
	entry, ok := algorithms[alg]
	if !ok {
		slog.Error("Backend JWT: unsupported algorithm", "algorithm", alg)
		return internalError()
	}
	issuer := getString(params, "issuer", "")
	expiry := parseDuration(getString(params, "tokenExpiry", ""), defaultTokenExpiry)
	headerName := getString(params, "header", defaultHeader)

	tokenCaching := getBool(params, "tokenCaching", true)

	// Resolve extra claims once — used for both the cache key and JWT population.
	extras := resolveExtraClaims(reqCtx, params)

	var cacheKey string
	if tokenCaching {
		cacheKey = buildTokenCacheKey(authCtx, reqCtx.APIName, reqCtx.Path, reqCtx.Method, extras)
		if signed, ok := p.getCachedToken(cacheKey); ok {
			slog.Debug("Backend JWT: cache hit", "authType", authTypeLabel(authCtx))
			return policy.UpstreamRequestHeaderModifications{
				HeadersToSet: map[string]string{headerName: signed},
			}
		}
	}

	signingMethod := entry.method
	var signKey interface{}
	if entry.keyType == "none" {
		signKey = jwt.UnsafeAllowNoneSignatureType
	} else {
		pemBytes, err := p.extractSigningKeyPEM(params)
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
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	if authCtx != nil && authCtx.Subject != "" {
		claims["sub"] = authCtx.Subject
	}
	if authCtx != nil && authCtx.AuthType != "" {
		claims["auth_type"] = authCtx.AuthType
	}
	if authCtx != nil && authCtx.Issuer != "" {
		claims["original_iss"] = authCtx.Issuer
	}
	if authCtx != nil && len(authCtx.Audience) > 0 {
		claims["aud"] = authCtx.Audience
	}
	if authCtx != nil && authCtx.CredentialID != "" {
		claims["credential_id"] = authCtx.CredentialID
	}
	// For JWT auth: forward all non-standard claims from the incoming token under their
	// original names. claimMappings and customClaims applied below can add aliases or override.
	if authCtx != nil && authCtx.AuthType == "jwt" {
		for k, v := range authCtx.Properties {
			if !restrictedClaims[k] {
				claims[k] = v
			}
		}
		if len(authCtx.Scopes) > 0 {
			scopes := make([]string, 0, len(authCtx.Scopes))
			for s := range authCtx.Scopes {
				scopes = append(scopes, s)
			}
			sort.Strings(scopes)
			claims["scope"] = strings.Join(scopes, " ")
		}
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

	if tokenCaching {
		p.putCachedToken(cacheKey, signed, expiry)
	}
	slog.Debug("Backend JWT: generated token", "header", headerName, "authType", authTypeLabel(authCtx))

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

// restrictedClaims are set by the policy itself; custom claims must not override them.
var restrictedClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"iat": true,
	"nbf": true,
	"jti": true,
}

// resolveExtraClaims resolves claimMappings and customClaims from params.
// claimMappings are processed first; customClaims run after and take precedence.
// stringClaims holds resolved string values (including $ctx: refs and mapped properties).
// rawClaims holds non-string customClaims preserved as their original types for JWT population.
func resolveExtraClaims(reqCtx *policy.RequestHeaderContext, params map[string]interface{}) resolvedClaims {
	result := resolvedClaims{
		stringClaims: make(map[string]string),
		rawClaims:    make(map[string]interface{}),
	}

	authCtx := reqCtx.SharedContext.AuthContext

	// Process claimMappings first so customClaims can override them.
	if raw, ok := params["claimMappings"]; ok {
		if cm, ok := raw.(map[string]interface{}); ok {
			for dest, srcRaw := range cm {
				src, ok := srcRaw.(string)
				if !ok || src == "" {
					continue
				}
				if restrictedClaims[dest] {
					slog.Warn("Backend JWT: claimMapping targets a reserved claim; skipping", "claim", dest)
					continue
				}
				if authCtx == nil {
					continue
				}
				val, ok := authCtx.Properties[src]
				if !ok {
					continue
				}
				result.stringClaims[dest] = val
			}
		}
	}

	if customRaw, ok := params["customClaims"]; ok {
		if custom, ok := customRaw.(map[string]interface{}); ok {
			for k, v := range custom {
				if restrictedClaims[k] {
					slog.Warn("Backend JWT: customClaim targets a reserved claim; skipping", "claim", k)
					continue
				}
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

// keyBufPool reuses byte buffers across cache key constructions to reduce GC pressure.
var keyBufPool = sync.Pool{New: func() interface{} { return new(bytes.Buffer) }}

// buildTokenCacheKey returns a cache key for the token cache.
//
//   - TokenId, no extras:  raw concatenation — TokenId + api name + path + method.
//   - TokenId, with extras: SHA256 of the above + resolved claim values.
//   - authCtx nil:          FNV-64a of api name + path + method + extras.
//   - otherwise:            FNV-64a of all identity fields + api name + path + method + extras.
//
// Extras (resolved customClaims / claimMappings) are included in all paths so that
// dynamic values such as $ctx:request.header.* produce distinct cache entries per request.
func buildTokenCacheKey(authCtx *policy.AuthContext, apiName, path, method string, extras resolvedClaims) string {
	if i := strings.IndexByte(path, '?'); i != -1 {
		path = path[:i]
	}

	var extraKeys []string
	if len(extras.stringClaims) > 0 || len(extras.rawClaims) > 0 {
		extraKeys = sortedExtraKeys(extras)
	}

	if authCtx != nil && authCtx.TokenId != "" {
		if len(extraKeys) == 0 {
			// Fast path: no extras, no hash needed.
			key := authCtx.TokenId + "\x00" + apiName + "\x00" + path + "\x00" + method
			slog.Debug("Backend JWT: cache key (TokenId)", "apiName", apiName, "path", path, "method", method, "cacheKey", key)
			return key
		}
		// Extras present: SHA256 to normalize key length.
		buf := keyBufPool.Get().(*bytes.Buffer)
		buf.Reset()
		buf.WriteString(authCtx.TokenId)
		buf.WriteByte('|')
		buf.WriteString(apiName)
		buf.WriteByte('|')
		buf.WriteString(path)
		buf.WriteByte('|')
		buf.WriteString(method)
		appendExtras(buf, extraKeys, extras)
		sum := sha256.Sum256(buf.Bytes())
		keyBufPool.Put(buf)
		key := fmt.Sprintf("%x", sum)
		slog.Debug("Backend JWT: cache key (TokenId+claims)", "apiName", apiName, "path", path, "method", method, "extraClaimKeys", extraKeys, "cacheKey", key)
		return key
	}

	buf := keyBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer keyBufPool.Put(buf)

	if authCtx == nil {
		buf.WriteString(apiName)
		buf.WriteByte('|')
		buf.WriteString(path)
		buf.WriteByte('|')
		buf.WriteString(method)
		appendExtras(buf, extraKeys, extras)
		key := fnvHash(buf)
		slog.Debug("Backend JWT: cache key (no-auth)", "apiName", apiName, "path", path, "method", method, "extraClaimKeys", extraKeys, "cacheKey", key)
		return key
	}

	// Non-nil authCtx without TokenId: include all available identity fields.
	buf.WriteString(authCtx.AuthType)
	buf.WriteByte('|')
	buf.WriteString(authCtx.Issuer)
	buf.WriteByte('|')
	buf.WriteString(authCtx.Subject)
	buf.WriteByte('|')
	buf.WriteString(authCtx.CredentialID)
	buf.WriteByte('|')
	buf.WriteString(strings.Join(sortedSlice(authCtx.Audience), ","))
	propKeys := make([]string, 0, len(authCtx.Properties))
	for k := range authCtx.Properties {
		propKeys = append(propKeys, k)
	}
	sort.Strings(propKeys)
	for _, k := range propKeys {
		buf.WriteByte('|')
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(authCtx.Properties[k])
	}
	if len(authCtx.Scopes) > 0 {
		scopeKeys := make([]string, 0, len(authCtx.Scopes))
		for s := range authCtx.Scopes {
			scopeKeys = append(scopeKeys, s)
		}
		sort.Strings(scopeKeys)
		buf.WriteByte('|')
		buf.WriteString("scope=")
		buf.WriteString(strings.Join(scopeKeys, " "))
	}
	buf.WriteByte('|')
	buf.WriteString(apiName)
	buf.WriteByte('|')
	buf.WriteString(path)
	buf.WriteByte('|')
	buf.WriteString(method)
	appendExtras(buf, extraKeys, extras)

	key := fnvHash(buf)
	slog.Debug("Backend JWT: cache key (identity hash)",
		"authType", authTypeLabel(authCtx),
		"apiName", apiName,
		"path", path,
		"method", method,
		"extraClaimKeys", extraKeys,
		"cacheKey", key,
	)
	return key
}

func fnvHash(buf *bytes.Buffer) string {
	h := fnv.New64a()
	h.Write(buf.Bytes())
	return fmt.Sprintf("%016x", h.Sum64())
}

func appendExtras(buf *bytes.Buffer, keys []string, extras resolvedClaims) {
	for _, k := range keys {
		buf.WriteByte('|')
		buf.WriteString(k)
		buf.WriteByte('=')
		if v, ok := extras.stringClaims[k]; ok {
			buf.WriteString(v)
		} else {
			fmt.Fprintf(buf, "%v", extras.rawClaims[k])
		}
	}
}


func sortedSlice(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

func sortedExtraKeys(extras resolvedClaims) []string {
	keys := make([]string, 0, len(extras.stringClaims)+len(extras.rawClaims))
	for k := range extras.stringClaims {
		keys = append(keys, k)
	}
	for k := range extras.rawClaims {
		if _, exists := extras.stringClaims[k]; !exists {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func authTypeLabel(authCtx *policy.AuthContext) string {
	if authCtx == nil {
		return "none"
	}
	return authCtx.AuthType
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
// Path-based keys are cached after the first read so that token cache misses under high load do not
// repeatedly hit the filesystem. Key rotation requires a gateway restart.
func (p *BackendJWTPolicy) extractSigningKeyPEM(params map[string]interface{}) ([]byte, error) {
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

		p.keyMu.RLock()
		cached, ok := p.pemCache[path]
		p.keyMu.RUnlock()
		if ok {
			return cached, nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file %q: %w", path, err)
		}

		p.keyMu.Lock()
		p.pemCache[path] = data
		p.keyMu.Unlock()

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

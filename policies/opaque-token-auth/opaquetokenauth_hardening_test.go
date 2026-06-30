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

package opaquetokenauth

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	return path
}

func TestEndpoint5xxRetriesThenFails(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionRetryCount"] = 2
	params["introspectionRetryInterval"] = "1ms"

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
	if got := atomic.LoadInt64(&calls); got != 3 {
		t.Errorf("introspection attempts = %d, want 3 (1 + 2 retries)", got)
	}
}

func TestRetryEventualSuccess(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionRetryCount"] = 3
	params["introspectionRetryInterval"] = "1ms"

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if got := atomic.LoadInt64(&calls); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestCacheHitSingleCall(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	p := newPolicy()

	for i := 0; i < 3; i++ {
		reqCtx, action := execute(t, p, params, bearerHeader("same-token"))
		assertSuccess(t, reqCtx, action)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Errorf("introspection calls = %d, want 1 (cached)", got)
	}
}

func TestCacheExpiryRefetch(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionCacheTtl"] = "20ms"
	p := newPolicy()

	reqCtx, action := execute(t, p, params, bearerHeader("same-token"))
	assertSuccess(t, reqCtx, action)
	time.Sleep(40 * time.Millisecond)
	reqCtx, action = execute(t, p, params, bearerHeader("same-token"))
	assertSuccess(t, reqCtx, action)

	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("introspection calls = %d, want 2 (cache expired)", got)
	}
}

func TestCacheNotUsedPastExp(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		// exp == now: cache window collapses to zero, but still valid within leeway.
		activeResponder(map[string]interface{}{"active": true, "sub": "u", "exp": time.Now().Unix()})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	params["introspectionCacheTtl"] = "60s" // large TTL, but exp bounds it
	p := newPolicy()

	for i := 0; i < 2; i++ {
		reqCtx, action := execute(t, p, params, bearerHeader("same-token"))
		assertSuccess(t, reqCtx, action)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("introspection calls = %d, want 2 (not cached past exp)", got)
	}
}

func TestCacheKeyedPerToken(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		_ = r.ParseForm()
		// Echo the presented token as the subject so we can detect cross-token leakage.
		activeResponder(map[string]interface{}{"active": true, "sub": r.PostFormValue("token")})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	p := newPolicy()

	reqCtx, action := execute(t, p, params, bearerHeader("token-A"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "token-A" {
		t.Fatalf("first subject = %q, want token-A", reqCtx.AuthContext.Subject)
	}

	reqCtx, action = execute(t, p, params, bearerHeader("token-B"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "token-B" {
		t.Errorf("second subject = %q, want token-B (no cache leakage)", reqCtx.AuthContext.Subject)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("calls = %d, want 2 (distinct tokens)", got)
	}
}

func TestInactiveNotCachedWhenNegativeCacheTtlIsZero(t *testing.T) {
	var calls int64
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		activeResponder(map[string]interface{}{"active": false})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))
	// Explicitly disable negative caching: inactive results must not be cached.
	params["introspectionNegativeCacheTtl"] = "0s"
	p := newPolicy()

	for i := 0; i < 2; i++ {
		reqCtx, action := execute(t, p, params, bearerHeader("same-token"))
		assertFailure(t, reqCtx, action, 401)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Errorf("calls = %d, want 2 (inactive results not cached when negativeCacheTtl=0)", got)
	}
}

func TestExpiredBeyondLeewayFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "exp": time.Now().Add(-time.Hour).Unix(),
	}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestExpiredWithinLeewaySucceeds(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "exp": time.Now().Add(-10 * time.Second).Unix(),
	}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["leeway"] = "30s"

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
}

func TestNotYetValidBeyondLeewayFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "nbf": time.Now().Add(time.Hour).Unix(),
	}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestTLSCustomCASucceeds(t *testing.T) {
	srv := httptest.NewTLSServer(activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	t.Cleanup(srv.Close)
	certPath := writeCertPEM(t, srv.Certificate())

	params := baseParams(provider("idp", srv.URL, map[string]interface{}{"certificatePath": certPath}))
	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
}

func TestTLSSkipVerifySucceeds(t *testing.T) {
	srv := httptest.NewTLSServer(activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	t.Cleanup(srv.Close)

	params := baseParams(provider("idp", srv.URL, map[string]interface{}{"skipTlsVerify": true}))
	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
}

func TestTLSUntrustedFails(t *testing.T) {
	srv := httptest.NewTLSServer(activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	t.Cleanup(srv.Close)

	params := baseParams(provider("idp", srv.URL, nil)) // no CA, no skip → cert untrusted
	params["introspectionRetryCount"] = 0

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestErrorMessageFormats(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))

	t.Run("json", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["errorMessageFormat"] = "json"
		params["errorMessage"] = "nope"
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		if ir.Headers["content-type"] != "application/json" {
			t.Errorf("content-type = %q", ir.Headers["content-type"])
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(ir.Body, &parsed); err != nil {
			t.Fatalf("body not json: %v", err)
		}
		if parsed["message"] != "nope" {
			t.Errorf("message = %v, want nope", parsed["message"])
		}
	})
	t.Run("plain", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["errorMessageFormat"] = "plain"
		params["errorMessage"] = "denied"
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		if ir.Headers["content-type"] != "text/plain" {
			t.Errorf("content-type = %q", ir.Headers["content-type"])
		}
		if string(ir.Body) != "denied" {
			t.Errorf("body = %q, want denied", string(ir.Body))
		}
	})
	t.Run("minimal", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["errorMessageFormat"] = "minimal"
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		ir := assertFailure(t, reqCtx, action, 401)
		if ir.Headers["content-type"] != "text/plain" {
			t.Errorf("content-type = %q, want text/plain", ir.Headers["content-type"])
		}
		if string(ir.Body) != "Unauthorized" {
			t.Errorf("body = %q, want Unauthorized", string(ir.Body))
		}
	})
}

func TestOnFailureStatusCode(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["onFailureStatusCode"] = 403

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 403)
}

func TestAuthContextSetOnFailure(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, _ := execute(t, newPolicy(), params, bearerHeader("tok"))
	if reqCtx.AuthContext == nil {
		t.Fatal("AuthContext should be set on failure")
	}
	if reqCtx.AuthContext.AuthType != AuthType {
		t.Errorf("AuthType = %q, want %q", reqCtx.AuthContext.AuthType, AuthType)
	}
	if reqCtx.AuthContext.Authenticated {
		t.Error("Authenticated should be false")
	}
}

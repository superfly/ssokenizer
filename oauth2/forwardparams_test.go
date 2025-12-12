package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
)

// TestForwardParams tests that parameters from the start URL are forwarded to both auth and token requests
func TestForwardParams(t *testing.T) {
	// Track which parameters the IDP received
	receivedAuthParams := make(map[string]string)
	receivedTokenParams := make(map[string]string)

	// Mock IDP that captures forwarded parameters
	idp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		username, password, _ := r.BasicAuth()

		switch r.URL.Path {
		case "/auth":
			// Capture auth request parameters
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					receivedAuthParams[key] = values[0]
				}
			}

			// Validate required params
			if r.URL.Query().Get("client_id") != testClientID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ru := r.URL.Query().Get("redirect_uri")
			if ru == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ruu, err := url.Parse(ru)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			params := make(url.Values)
			params.Set("code", "111")
			params.Set("state", r.URL.Query().Get("state"))
			ruu.RawQuery = params.Encode()

			http.Redirect(w, r, ruu.String(), http.StatusFound)
			return

		case "/token":
			// Capture token request parameters
			for key, values := range r.Form {
				if len(values) > 0 {
					receivedTokenParams[key] = values[0]
				}
			}

			if username != testClientID || password != testClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			if r.Form.Get("code") != "111" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "999", "token_type": "Bearer", "refresh_token": "888", "expires_in": 3600}`))
			return

		case "/api":
			if r.Header.Get("Authorization") != "Bearer 999" {
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}
	})

	// Setup test servers
	rpServer := httptest.NewServer(rp)
	t.Cleanup(rpServer.Close)
	returnURL, err := url.Parse(rpServer.URL)
	assert.NoError(t, err)

	idpServer := httptest.NewServer(idp)
	t.Cleanup(idpServer.Close)

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkz := tokenizer.NewTokenizer(openKey)
	tkz.Tr = http.DefaultTransport.(*http.Transport)
	tkzServer := httptest.NewServer(tkz)
	t.Cleanup(tkzServer.Close)

	providers := make(ssokenizer.StaticProviderRegistry)
	skz := ssokenizer.NewServer(providers)
	assert.NoError(t, skz.Start("127.0.0.1:"))
	t.Cleanup(func() {
		skz.Shutdown(nil)
		<-skz.Done
	})

	skzURL, err := url.Parse("http://" + skz.Address)
	assert.NoError(t, err)
	providerURL := skzURL.JoinPath("/vanta")

	// Configure provider with ForwardParams for source_id (like Vanta)
	providers["vanta"] = &Provider{
		ProviderConfig: ssokenizer.ProviderConfig{
			Tokenizer: ssokenizer.TokenizerConfig{
				SealKey: sealKey,
				Auth:    tokenizer.NewBearerAuthConfig(rpAuth),
			},
			URL:       *providerURL,
			ReturnURL: *returnURL,
		},
		OAuthConfig: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  idpServer.URL + "/auth",
				TokenURL: idpServer.URL + "/token",
			},
		},
		ForwardParams: []string{"source_id"},
	}

	// Test the OAuth flow with source_id parameter
	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar = noSecureJar{client.Jar}

	// Start OAuth flow with source_id parameter
	resp, err := client.Get("http://" + skz.Address + "/vanta/start?source_id=test-source-123")
	assert.NoError(t, err)
	sealed := checkResponse(t, resp, rpServer.URL, "")

	// Verify source_id was forwarded to auth request
	assert.Equal(t, "test-source-123", receivedAuthParams["source_id"], "source_id should be forwarded to auth request")

	// Verify source_id was forwarded to token request
	assert.Equal(t, "test-source-123", receivedTokenParams["source_id"], "source_id should be forwarded to token request")

	// Verify the sealed token works
	tkzClient, err := tokenizer.Client(tkzServer.URL, tokenizer.WithAuth(rpAuth), tokenizer.WithSecret(sealed, nil))
	assert.NoError(t, err)
	resp, err = tkzClient.Get(idpServer.URL + "/api")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestForwardParamsMultiple tests forwarding multiple parameters
func TestForwardParamsMultiple(t *testing.T) {
	receivedAuthParams := make(map[string]string)
	receivedTokenParams := make(map[string]string)

	idp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		username, password, _ := r.BasicAuth()

		switch r.URL.Path {
		case "/auth":
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					receivedAuthParams[key] = values[0]
				}
			}

			if r.URL.Query().Get("client_id") != testClientID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ru := r.URL.Query().Get("redirect_uri")
			if ru == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ruu, err := url.Parse(ru)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			params := make(url.Values)
			params.Set("code", "111")
			params.Set("state", r.URL.Query().Get("state"))
			ruu.RawQuery = params.Encode()

			http.Redirect(w, r, ruu.String(), http.StatusFound)
			return

		case "/token":
			for key, values := range r.Form {
				if len(values) > 0 {
					receivedTokenParams[key] = values[0]
				}
			}

			if username != testClientID || password != testClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "999", "token_type": "Bearer", "refresh_token": "888", "expires_in": 3600}`))
			return
		}
	})

	rpServer := httptest.NewServer(rp)
	t.Cleanup(rpServer.Close)
	returnURL, err := url.Parse(rpServer.URL)
	assert.NoError(t, err)

	idpServer := httptest.NewServer(idp)
	t.Cleanup(idpServer.Close)

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkz := tokenizer.NewTokenizer(openKey)
	tkz.Tr = http.DefaultTransport.(*http.Transport)
	tkzServer := httptest.NewServer(tkz)
	t.Cleanup(tkzServer.Close)

	providers := make(ssokenizer.StaticProviderRegistry)
	skz := ssokenizer.NewServer(providers)
	assert.NoError(t, skz.Start("127.0.0.1:"))
	t.Cleanup(func() {
		skz.Shutdown(nil)
		<-skz.Done
	})

	skzURL, err := url.Parse("http://" + skz.Address)
	assert.NoError(t, err)
	providerURL := skzURL.JoinPath("/test")

	// Configure provider to forward multiple params (like Google's hd)
	providers["test"] = &Provider{
		ProviderConfig: ssokenizer.ProviderConfig{
			Tokenizer: ssokenizer.TokenizerConfig{
				SealKey: sealKey,
				Auth:    tokenizer.NewBearerAuthConfig(rpAuth),
			},
			URL:       *providerURL,
			ReturnURL: *returnURL,
		},
		OAuthConfig: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  idpServer.URL + "/auth",
				TokenURL: idpServer.URL + "/token",
			},
		},
		ForwardParams: []string{"source_id", "hd", "tenant"},
	}

	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar = noSecureJar{client.Jar}

	// Start OAuth flow with multiple forwarded parameters
	resp, err := client.Get("http://" + skz.Address + "/test/start?source_id=test-123&hd=example.com&tenant=acme")
	assert.NoError(t, err)
	checkResponse(t, resp, rpServer.URL, "")

	// Verify all params were forwarded to auth request
	assert.Equal(t, "test-123", receivedAuthParams["source_id"])
	assert.Equal(t, "example.com", receivedAuthParams["hd"])
	assert.Equal(t, "acme", receivedAuthParams["tenant"])

	// Verify all params were forwarded to token request
	assert.Equal(t, "test-123", receivedTokenParams["source_id"])
	assert.Equal(t, "example.com", receivedTokenParams["hd"])
	assert.Equal(t, "acme", receivedTokenParams["tenant"])
}

// TestForwardParamsMissing tests that missing forwarded parameters don't cause errors
func TestForwardParamsMissing(t *testing.T) {
	receivedAuthParams := make(map[string]string)

	idp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		username, password, _ := r.BasicAuth()

		switch r.URL.Path {
		case "/auth":
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					receivedAuthParams[key] = values[0]
				}
			}

			if r.URL.Query().Get("client_id") != testClientID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ru := r.URL.Query().Get("redirect_uri")
			if ru == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ruu, err := url.Parse(ru)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			params := make(url.Values)
			params.Set("code", "111")
			params.Set("state", r.URL.Query().Get("state"))
			ruu.RawQuery = params.Encode()

			http.Redirect(w, r, ruu.String(), http.StatusFound)
			return

		case "/token":
			if username != testClientID || password != testClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "999", "token_type": "Bearer", "refresh_token": "888", "expires_in": 3600}`))
			return
		}
	})

	rpServer := httptest.NewServer(rp)
	t.Cleanup(rpServer.Close)
	returnURL, err := url.Parse(rpServer.URL)
	assert.NoError(t, err)

	idpServer := httptest.NewServer(idp)
	t.Cleanup(idpServer.Close)

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkz := tokenizer.NewTokenizer(openKey)
	tkz.Tr = http.DefaultTransport.(*http.Transport)
	tkzServer := httptest.NewServer(tkz)
	t.Cleanup(tkzServer.Close)

	providers := make(ssokenizer.StaticProviderRegistry)
	skz := ssokenizer.NewServer(providers)
	assert.NoError(t, skz.Start("127.0.0.1:"))
	t.Cleanup(func() {
		skz.Shutdown(nil)
		<-skz.Done
	})

	skzURL, err := url.Parse("http://" + skz.Address)
	assert.NoError(t, err)
	providerURL := skzURL.JoinPath("/test")

	providers["test"] = &Provider{
		ProviderConfig: ssokenizer.ProviderConfig{
			Tokenizer: ssokenizer.TokenizerConfig{
				SealKey: sealKey,
				Auth:    tokenizer.NewBearerAuthConfig(rpAuth),
			},
			URL:       *providerURL,
			ReturnURL: *returnURL,
		},
		OAuthConfig: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  idpServer.URL + "/auth",
				TokenURL: idpServer.URL + "/token",
			},
		},
		ForwardParams: []string{"source_id"},
	}

	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar = noSecureJar{client.Jar}

	// Start OAuth flow WITHOUT source_id parameter
	resp, err := client.Get("http://" + skz.Address + "/test/start")
	assert.NoError(t, err)
	checkResponse(t, resp, rpServer.URL, "")

	// Verify source_id was NOT added to auth request (since it wasn't in the start URL)
	_, exists := receivedAuthParams["source_id"]
	assert.False(t, exists, "source_id should not be present when not provided in start URL")
}

// TestForwardParamsWithStaticParams tests that ForwardParams and static params can coexist
func TestForwardParamsWithStaticParams(t *testing.T) {
	receivedAuthParams := make(map[string]string)
	receivedTokenParams := make(map[string]string)

	idp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		username, password, _ := r.BasicAuth()

		switch r.URL.Path {
		case "/auth":
			for key, values := range r.URL.Query() {
				if len(values) > 0 {
					receivedAuthParams[key] = values[0]
				}
			}

			if r.URL.Query().Get("client_id") != testClientID {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ru := r.URL.Query().Get("redirect_uri")
			if ru == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ruu, err := url.Parse(ru)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			params := make(url.Values)
			params.Set("code", "111")
			params.Set("state", r.URL.Query().Get("state"))
			ruu.RawQuery = params.Encode()

			http.Redirect(w, r, ruu.String(), http.StatusFound)
			return

		case "/token":
			for key, values := range r.Form {
				if len(values) > 0 {
					receivedTokenParams[key] = values[0]
				}
			}

			if username != testClientID || password != testClientSecret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "999", "token_type": "Bearer", "refresh_token": "888", "expires_in": 3600}`))
			return
		}
	})

	rpServer := httptest.NewServer(rp)
	t.Cleanup(rpServer.Close)
	returnURL, err := url.Parse(rpServer.URL)
	assert.NoError(t, err)

	idpServer := httptest.NewServer(idp)
	t.Cleanup(idpServer.Close)

	pub, priv, _ := box.GenerateKey(rand.Reader)
	sealKey := hex.EncodeToString(pub[:])
	openKey := hex.EncodeToString(priv[:])

	tkz := tokenizer.NewTokenizer(openKey)
	tkz.Tr = http.DefaultTransport.(*http.Transport)
	tkzServer := httptest.NewServer(tkz)
	t.Cleanup(tkzServer.Close)

	providers := make(ssokenizer.StaticProviderRegistry)
	skz := ssokenizer.NewServer(providers)
	assert.NoError(t, skz.Start("127.0.0.1:"))
	t.Cleanup(func() {
		skz.Shutdown(nil)
		<-skz.Done
	})

	skzURL, err := url.Parse("http://" + skz.Address)
	assert.NoError(t, err)
	providerURL := skzURL.JoinPath("/test")

	// Configure with both ForwardParams and static params
	providers["test"] = &Provider{
		ProviderConfig: ssokenizer.ProviderConfig{
			Tokenizer: ssokenizer.TokenizerConfig{
				SealKey: sealKey,
				Auth:    tokenizer.NewBearerAuthConfig(rpAuth),
			},
			URL:       *providerURL,
			ReturnURL: *returnURL,
		},
		OAuthConfig: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  idpServer.URL + "/auth",
				TokenURL: idpServer.URL + "/token",
			},
		},
		ForwardParams:      []string{"source_id"},
		AuthRequestParams:  map[string]string{"audience": "https://api.example.com"},
		TokenRequestParams: map[string]string{"resource": "https://api.example.com"},
	}

	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar = noSecureJar{client.Jar}

	resp, err := client.Get("http://" + skz.Address + "/test/start?source_id=dynamic-123")
	assert.NoError(t, err)
	checkResponse(t, resp, rpServer.URL, "")

	// Verify both dynamic and static params are present in auth request
	assert.Equal(t, "dynamic-123", receivedAuthParams["source_id"], "dynamic param should be forwarded")
	assert.Equal(t, "https://api.example.com", receivedAuthParams["audience"], "static param should be present")

	// Verify both dynamic and static params are present in token request
	assert.Equal(t, "dynamic-123", receivedTokenParams["source_id"], "dynamic param should be forwarded")
	assert.Equal(t, "https://api.example.com", receivedTokenParams["resource"], "static param should be present")
}

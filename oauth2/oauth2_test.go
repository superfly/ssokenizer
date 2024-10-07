package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

const rpAuth = "555"

func setupTestServers(t *testing.T) (*httptest.Server, *ssokenizer.Server, *httptest.Server, *httptest.Server) {
	rpServer := httptest.NewServer(rp)
	t.Cleanup(rpServer.Close)
	t.Logf("rp=%s", rpServer.URL)

	idpServer := httptest.NewServer(idp)
	t.Cleanup(idpServer.Close)
	t.Logf("idp=%s", idpServer.URL)

	var (
		pub, priv, _ = box.GenerateKey(rand.Reader)
		sealKey      = hex.EncodeToString(pub[:])
		openKey      = hex.EncodeToString(priv[:])
	)

	tkz := tokenizer.NewTokenizer(openKey)
	tkz.Tr = http.DefaultTransport.(*http.Transport) // disable TLS requirement for app server
	tkzServer := httptest.NewServer(tkz)
	t.Cleanup(tkzServer.Close)

	skz := ssokenizer.NewServer(sealKey)
	assert.NoError(t, skz.Start("127.0.0.1:"))
	t.Logf("skz=http://%s", skz.Address)
	t.Cleanup(func() {
		assert.NoError(t, skz.Shutdown(context.Background()))
		<-skz.Done
		assert.NoError(t, skz.Err)
	})

	assert.NoError(t, skz.AddProvider("idp", Config{
		Path: "/idp",
		Config: oauth2.Config{
			ClientID:     testClientID,
			ClientSecret: testClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  idpServer.URL + "/auth",
				TokenURL: idpServer.URL + "/token",
			},
			Scopes: []string{"my scope"},
		},
	}, rpServer.URL, tokenizer.NewBearerAuthConfig(rpAuth)))
	return rpServer, skz, tkzServer, idpServer
}

func checkResponse(t *testing.T, resp *http.Response, expectedPrefix, expectedState string) string {
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Request.URL.String(), expectedPrefix))
	state := resp.Request.URL.Query().Get("state")
	assert.Equal(t, expectedState, state)
	errMsg := resp.Request.URL.Query().Get("error")
	assert.Equal(t, "", errMsg)
	sealed := resp.Request.URL.Query().Get("sealed")
	assert.NotEqual(t, "", sealed)
	sexpires := resp.Request.URL.Query().Get("expires")
	iexpires, err := strconv.ParseInt(sexpires, 10, 64)
	assert.NoError(t, err)
	expires := time.Unix(iexpires, 0)
	assert.Equal(t, 3599, time.Until(expires)/time.Second)
	return sealed
}

func TestOauth2(t *testing.T) {
	rpServer, skz, tkzServer, idpServer := setupTestServers(t)

	client := new(http.Client)
	client.Jar, _ = cookiejar.New(nil)
	client.Jar = noSecureJar{client.Jar}

	resp, err := client.Get("http://" + skz.Address + "/idp/start")
	assert.NoError(t, err)
	sealed := checkResponse(t, resp, rpServer.URL, "")

	tkzClient, err := tokenizer.Client(tkzServer.URL, tokenizer.WithAuth(rpAuth), tokenizer.WithSecret(sealed, nil))
	assert.NoError(t, err)
	resp, err = tkzClient.Get(idpServer.URL + "/api")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	withRefresh := map[string]string{tokenizer.ParamSubtoken: tokenizer.SubtokenRefresh}
	refreshClient, err := tokenizer.Client(tkzServer.URL, tokenizer.WithAuth(rpAuth), tokenizer.WithSecret(sealed, withRefresh))
	assert.NoError(t, err)
	resp, err = refreshClient.Get("http://" + skz.Address + "/idp/refresh")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	bldr := new(strings.Builder)
	_, err = io.Copy(bldr, resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "private, max-age=3599", resp.Header.Get("Cache-Control"))

	sealed = bldr.String()
	tkzClient, err = tokenizer.Client(tkzServer.URL, tokenizer.WithAuth(rpAuth), tokenizer.WithSecret(sealed, nil))
	assert.NoError(t, err)
	resp, err = tkzClient.Get(idpServer.URL + "/api")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// tests that when two parallel flows are initiated, they do not interfere and the second can
// complete successfully.
func TestOauth2Parallel(t *testing.T) {
	rpServer, skz, _, idpServer := setupTestServers(t)

	sharedJar, _ := cookiejar.New(nil)

	clientA := new(http.Client)
	clientA.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), idpServer.URL) {
			return nil // follow redirect to idp
		}
		return http.ErrUseLastResponse // don't follow redirect back from idp, simulating abandoned flow.
	}
	clientA.Jar = noSecureJar{sharedJar}
	_, err := clientA.Get("http://" + skz.Address + "/idp/start?state=first")
	assert.NoError(t, err)

	clientB := new(http.Client)
	clientB.Jar = noSecureJar{sharedJar}

	resp, err := clientB.Get("http://" + skz.Address + "/idp/start?state=second")
	assert.NoError(t, err)
	checkResponse(t, resp, rpServer.URL, "second")
}

const (
	testClientID     = "my-client-id"
	testClientSecret = "my-client-secret"
)

var idp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username, password, _ := r.BasicAuth()
	authorization := r.Header.Get("Authorization")

	logrus.WithFields(logrus.Fields{
		"server":        "idp",
		"method":        r.Method,
		"url":           r.URL.String(),
		"form":          r.Form,
		"username":      username,
		"password":      password,
		"authorization": authorization,
	}).Info()

	switch r.URL.Path {
	case "/auth":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		query := r.URL.Query()

		switch query.Get("client_id") {
		case testClientID:
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ru := query.Get("redirect_uri")
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
		params.Set("state", query.Get("state"))
		ruu.RawQuery = params.Encode()

		http.Redirect(w, r, ruu.String(), http.StatusFound)
		return
	case "/token":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if username != testClientID || password != testClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.Form.Get("code") == "111":
		case r.Form.Get("refresh_token") == "888":
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "999", "token_type": "Bearer", "refresh_token": "888", "expires_in": 3600}`))
		return
	case "/api":
		if authorization != "Bearer 999" {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}
})

var rp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"server": "rp",
		"method": r.Method,
		"url":    r.URL.String(),
		"form":   r.Form,
	}).Info()
})

type noSecureJar struct {
	http.CookieJar
}

func (j noSecureJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, cookie := range cookies {
		cookie.Secure = false
	}
	j.CookieJar.SetCookies(u, cookies)
}

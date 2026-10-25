package oauth2

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alecthomas/assert/v2"
	"golang.org/x/oauth2"
)

func TestWriteOAuth2Error(t *testing.T) {
	type want struct {
		status      int
		body        string
		contentType string // "" => header MUST be absent
	}

	cases := []struct {
		name string
		err  error
		want want
	}{
		// full RFC §5.2 fields pass through
		{
			name: "classified_full_fields",
			err: &oauth2.RetrieveError{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "Token expired",
				ErrorURI:         "https://provider/errors/invalid_grant",
			},
			want: want{
				status:      http.StatusBadGateway,
				body:        `{"error":"invalid_grant","error_description":"Token expired","error_uri":"https://provider/errors/invalid_grant"}`,
				contentType: "application/json",
			},
		},

		// arbitrary code passes through verbatim (covers the six RFC §5.2
		// codes plus provider-specific values).
		{
			name: "provider_specific_passthrough",
			err:  &oauth2.RetrieveError{ErrorCode: "bad_refresh_token"},
			want: want{http.StatusBadGateway, `{"error":"bad_refresh_token"}`, "application/json"},
		},

		// empty optional fields are omitted (omitempty)
		{
			name: "omitempty_description_and_uri",
			err: &oauth2.RetrieveError{
				ErrorCode:        "invalid_grant",
				ErrorDescription: "",
				ErrorURI:         "",
			},
			want: want{http.StatusBadGateway, `{"error":"invalid_grant"}`, "application/json"},
		},

		// wrapped error is unwrapped via errors.As
		{
			name: "wrapped_retrieve_error",
			err:  fmt.Errorf("token refresh: %w", &oauth2.RetrieveError{ErrorCode: "invalid_grant"}),
			want: want{http.StatusBadGateway, `{"error":"invalid_grant"}`, "application/json"},
		},

		// non-RetrieveError (transport-level) → empty body, no Content-Type
		{
			name: "transport_error_url_error",
			err: &url.Error{
				Op:  "Post",
				URL: "https://idp/token",
				Err: errors.New("dial tcp: connection refused"),
			},
			want: want{status: http.StatusBadGateway, body: "", contentType: ""},
		},

		// nil err is defensive (no panic, empty body)
		{
			name: "nil_error",
			err:  nil,
			want: want{status: http.StatusBadGateway, body: "", contentType: ""},
		},

		// empty ErrorCode + HTML Body + Response → empty body
		{
			name: "empty_code_with_html_body",
			err: &oauth2.RetrieveError{
				ErrorCode: "",
				Body:      []byte("<html>500 Internal Server Error</html>"),
				Response:  &http.Response{StatusCode: 500},
			},
			want: want{status: http.StatusBadGateway, body: "", contentType: ""},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeOAuth2Error(rec, http.StatusBadGateway, c.err)

			assert.Equal(t, c.want.status, rec.Code, "status code")
			assert.Equal(t, c.want.body, rec.Body.String(), "body")
			assert.Equal(t, c.want.contentType, rec.Header().Get("Content-Type"), "Content-Type")

			// Cache-prevention headers MUST be on every response (RFC 6749 §5.1).
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "Cache-Control")
			assert.Equal(t, "no-cache", rec.Header().Get("Pragma"), "Pragma")
		})
	}
}

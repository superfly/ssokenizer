package oauth2

import (
	"encoding/json"
	"errors"
	"net/http"

	"golang.org/x/oauth2"
)

// writeOAuth2Error writes an RFC 6749 §5.2 error response: a JSON body
// when err unwraps to a *oauth2.RetrieveError with a non-empty ErrorCode,
// empty body otherwise. RFC §5.1 cache-prevention headers are set on
// every response. Logging is the caller's responsibility.
func writeOAuth2Error(w http.ResponseWriter, status int, err error) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	var re *oauth2.RetrieveError
	if !errors.As(err, &re) || re.ErrorCode == "" {
		w.WriteHeader(status)
		return
	}

	body, _ := json.Marshal(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
		ErrorURI         string `json:"error_uri,omitempty"`
	}{
		Error:            re.ErrorCode,
		ErrorDescription: re.ErrorDescription,
		ErrorURI:         re.ErrorURI,
	})

	h.Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

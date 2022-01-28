package csrf

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
)

const (
	cookieName    = "csrf_token"
	formFieldName = "csrf_token"
	headerName    = "X-CSRF-Token"
	tokenLength   = 32
	maxAge        = 365 * 24 * 60 * 60
)

type key int

var csrfKey key = 1

func Token(r *http.Request) string {
	return r.Context().Value(csrfKey).(string)
}

func generateToken() ([]byte, error) {
	bytes := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to read random data: %w", err)
	}

	return bytes, nil
}

func getTokenFromCookie(r *http.Request) []byte {
	var token []byte

	cookie, err := r.Cookie(cookieName)
	if err == nil {
		token = b64decode(cookie.Value)
	}

	return token
}

func getTokenFromRequest(r *http.Request) []byte {
	var token string

	token = r.Header.Get(headerName)

	if token == "" {
		token = r.PostFormValue(formFieldName)
	}

	if token == "" && r.MultipartForm != nil {
		vals := r.MultipartForm.Value[formFieldName]
		if len(vals) != 0 {
			token = vals[0]
		}
	}

	return b64decode(token)
}

func setTokenCookie(w http.ResponseWriter, token []byte) {
	cookie := http.Cookie{}
	cookie.Name = cookieName
	cookie.Value = b64encode(token)
	cookie.Path = "/"
	cookie.MaxAge = maxAge

	http.SetCookie(w, &cookie)
}

func setTokenContext(r *http.Request, token []byte) (*http.Request, error) {
	maskedToken, err := maskToken(token)
	if err != nil {
		return r, err
	}

	return r.WithContext(context.WithValue(r.Context(), csrfKey, b64encode(maskedToken))), nil
}

func verifyToken(realToken, sentToken []byte) (bool, error) {
	realN := len(realToken)
	sentN := len(sentToken)

	if realN != tokenLength || sentN != tokenLength*2 {
		return false, ErrTokenInvalidLength
	}

	sentPlain, err := unmaskToken(sentToken)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(realToken, sentPlain) == 1, nil
}

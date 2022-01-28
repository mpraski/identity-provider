package csrf

import (
	"net/http"
	"net/url"

	"github.com/julienschmidt/httprouter"
)

var exemptMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodOptions,
	http.MethodTrace,
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

var DefaultErrorHandler = defaultErrorHandler

func Protect(h httprouter.Handle) httprouter.Handle {
	return protect(h)
}

func WithToken(r *http.Request, data map[string]interface{}) map[string]interface{} {
	data["token"] = Token(r)
	return data
}

func protect(h httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		w.Header().Add("Vary", "Cookie")

		realToken := getTokenFromCookie(r)

		if len(realToken) != tokenLength {
			token, err := generateToken()
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}

			setTokenCookie(w, token)

			r, err = setTokenContext(r, token)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		} else {
			var err error
			r, err = setTokenContext(r, realToken)
			if err != nil {
				DefaultErrorHandler(w, r)
				return
			}
		}

		if stringInSlice(r.Method, exemptMethods) {
			h(w, r, p)
			return
		}

		if r.URL.Scheme == "https" {
			referrer, err := url.Parse(r.Header.Get("Referrer"))

			if err != nil || referrer.String() == "" {
				DefaultErrorHandler(w, r)
				return
			}

			if !sameOrigin(referrer, r.URL) {
				DefaultErrorHandler(w, r)
				return
			}
		}

		sentToken := getTokenFromRequest(r)

		tokenOk, err := verifyToken(realToken, sentToken)
		if err != nil {
			DefaultErrorHandler(w, r)
			return
		}

		if !tokenOk {
			DefaultErrorHandler(w, r)
			return
		}

		h(w, r, p)
	}
}

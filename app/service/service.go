package service

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/mpraski/identity-provider/app/csrf"
	"github.com/mpraski/identity-provider/app/provider"
	"github.com/mpraski/identity-provider/app/template"
	hydraAdmin "github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
)

type Service struct {
	renderer  *template.Renderer
	providers provider.Providers
	hydra     hydraAdmin.ClientService
}

const (
	loginChallengeKey   = "login_challenge"
	consentChallengeKey = "consent_challenge"
	grantScopeKey       = "grant_scope"
	rememberFor         = 3600
)

func New(
	renderer *template.Renderer,
	providers provider.Providers,
	hydra hydraAdmin.ClientService,
) *Service {
	return &Service{
		renderer:  renderer,
		providers: providers,
		hydra:     hydra,
	}
}

func (s *Service) Router() http.Handler {
	r := httprouter.New()

	r.GET("/authentication/login", csrf.Protect(s.beginLogin))
	r.POST("/authentication/login", csrf.Protect(s.completeLogin))
	r.GET("/authentication/consent", csrf.Protect(s.beginConsent))
	r.POST("/authentication/consent", csrf.Protect(s.completeConsent))

	return r
}

func (s *Service) beginLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	challenge := strings.TrimSpace(r.URL.Query().Get(loginChallengeKey))
	if challenge == "" {
		_ = s.renderer.Render(w, http.StatusOK, "login", csrf.WithToken(r, map[string]interface{}{
			"ErrorName":    "login_challenge_missing",
			"ErrorContent": "Login challenge is missing!",
		}))

		return
	}

	params := hydraAdmin.NewGetLoginRequestParams()
	params.WithContext(r.Context())
	params.SetLoginChallenge(challenge)

	req, err := s.hydra.GetLoginRequest(params)
	if err != nil {
		_ = s.renderer.Render(w, http.StatusOK, "login", csrf.WithToken(r, map[string]interface{}{
			"ErrorName":    "login_request_failed",
			"ErrorContent": "Failed to get login request info",
		}))

		return
	}

	var skip bool
	if req.GetPayload().Skip != nil {
		skip = *req.GetPayload().Skip
	}

	if skip {
		params := hydraAdmin.NewAcceptLoginRequestParams()
		params.WithContext(r.Context())
		params.SetLoginChallenge(challenge)
		params.SetBody(&models.AcceptLoginRequest{
			Subject: req.GetPayload().Subject,
		})

		reqAccept, err := s.hydra.AcceptLoginRequest(params)
		if err != nil {
			_ = s.renderer.Render(w, http.StatusOK, "login", csrf.WithToken(r, map[string]interface{}{
				"ErrorName":    "accept_login_request_failed",
				"ErrorContent": "Failed to accept login request",
			}))

			return
		}

		http.Redirect(w, r, *reqAccept.GetPayload().RedirectTo, http.StatusFound)

		return
	}

	_ = s.renderer.Render(w, http.StatusOK, "login", csrf.WithToken(r, map[string]interface{}{
		"LoginChallenge": challenge,
	}))
}

func (s *Service) completeLogin(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var (
		loginChallenge = strings.TrimSpace(r.PostFormValue(loginChallengeKey))
		email          = strings.TrimSpace(r.PostFormValue("email"))
		password       = strings.TrimSpace(r.PostFormValue("password"))
		rememberMe     = strings.TrimSpace(r.PostFormValue("remember_me"))
	)

	if loginChallenge == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	i, err := s.providers[provider.Account].Provide(r.Context(), provider.Credentials{
		"email":    email,
		"password": password,
	})

	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	params := hydraAdmin.NewGetLoginRequestParams()
	params.SetLoginChallenge(loginChallenge)

	if _, err = s.hydra.GetLoginRequest(params); err != nil {
		http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
		return
	}

	acceptParams := hydraAdmin.NewAcceptLoginRequestParams()
	acceptParams.WithContext(r.Context())
	acceptParams.SetLoginChallenge(loginChallenge)
	acceptParams.SetBody(&models.AcceptLoginRequest{
		Subject:     &i,
		Remember:    rememberMe == "true",
		RememberFor: rememberFor,
	})

	reqAccept, err := s.hydra.AcceptLoginRequest(acceptParams)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
		return
	}

	http.Redirect(w, r, *reqAccept.GetPayload().RedirectTo, http.StatusFound)
}

func (s *Service) beginConsent(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	challenge := strings.TrimSpace(r.URL.Query().Get(consentChallengeKey))
	if challenge == "" {
		_ = s.renderer.Render(w, http.StatusOK, "consent", csrf.WithToken(r, map[string]interface{}{
			"ErrorName":    "consent_challenge_missing",
			"ErrorContent": "Consent challenge is missing!",
		}))

		return
	}

	params := hydraAdmin.NewGetConsentRequestParams()
	params.WithContext(r.Context())
	params.SetConsentChallenge(challenge)

	req, err := s.hydra.GetConsentRequest(params)
	if err != nil {
		_ = s.renderer.Render(w, http.StatusOK, "consent", csrf.WithToken(r, map[string]interface{}{
			"ErrorName":    "consent_request_failed",
			"ErrorContent": "Failed to get consent request info",
		}))

		return
	}

	if req.GetPayload().Skip {
		params := hydraAdmin.NewAcceptConsentRequestParams()
		params.WithContext(r.Context())
		params.SetConsentChallenge(challenge)
		params.WithBody(&models.AcceptConsentRequest{
			GrantAccessTokenAudience: req.GetPayload().RequestedAccessTokenAudience,
			GrantScope:               req.GetPayload().RequestedScope,
		})

		reqAccept, err := s.hydra.AcceptConsentRequest(params)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
			return
		}

		http.Redirect(w, r, *reqAccept.GetPayload().RedirectTo, http.StatusFound)

		return
	}

	consentMessage := fmt.Sprintf("Application %s wants access resources on your behalf and to:",
		req.GetPayload().Client.ClientName,
	)

	_ = s.renderer.Render(w, http.StatusOK, "consent", csrf.WithToken(r, map[string]interface{}{
		"ConsentChallenge": challenge,
		"ConsentMessage":   consentMessage,
		"RequestedScopes":  req.GetPayload().RequestedScope,
	}))
}

func (s *Service) completeConsent(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var (
		consentChallenge = strings.TrimSpace(r.PostFormValue(consentChallengeKey))
		grantScope       = r.Form[grantScopeKey]
	)

	if consentChallenge == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	params := hydraAdmin.NewGetConsentRequestParams()
	params.WithContext(r.Context())
	params.SetConsentChallenge(consentChallenge)

	req, err := s.hydra.GetConsentRequest(params)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
		return
	}

	acceptParams := hydraAdmin.NewAcceptConsentRequestParams()
	acceptParams.WithContext(r.Context())
	acceptParams.SetConsentChallenge(consentChallenge)
	acceptParams.WithBody(&models.AcceptConsentRequest{
		GrantAccessTokenAudience: req.GetPayload().RequestedAccessTokenAudience,
		GrantScope:               grantScope,
	})

	reqAccept, err := s.hydra.AcceptConsentRequest(acceptParams)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
		return
	}

	http.Redirect(w, r, *reqAccept.GetPayload().RedirectTo, http.StatusFound)
}

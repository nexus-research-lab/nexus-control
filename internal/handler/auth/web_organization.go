package auth

import (
	"net/http"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webOrganizationAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireWebMutationOrigin(w, r) {
			return
		}
		principal, ok := s.requireWebPrincipal(w, r)
		if !ok {
			return
		}
		var input authservice.OrganizationInput
		if !s.decode(w, r, &input) {
			return
		}
		if err := s.service.MutateOrganization(r.Context(), *principal, action, input); err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		s.webStatus(w, r)
	}
}

func (s *HTTPServer) webRegister(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	var input authservice.LoginInput
	if !s.decode(w, r, &input) {
		return
	}
	if err := s.service.RegisterAccount(r.Context(), input); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	input.ClientIP, input.UserAgent = webClientIP(r), r.UserAgent()
	result, err := s.service.Login(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(result.SessionToken, false))
	s.writeWebStatus(w, r, &result.Principal)
}

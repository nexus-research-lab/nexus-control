package auth

import (
	"net/http"
	"net/url"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webListOrganizationInvitations(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	result, err := s.service.ListOrganizationInvitations(r.Context(), *principal)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func (s *HTTPServer) webCreateOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.CreateOrganizationInvitationInput
	if !s.decode(w, r, &input) {
		return
	}
	result, err := s.service.CreateOrganizationInvitation(r.Context(), *principal, input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	result.JoinURL = webRequestOrigin(r) + "/join/" + url.PathEscape(result.Token)
	s.writeData(w, r, result)
}

func (s *HTTPServer) webRevokeOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	s.webMutateOrganizationInvitation(w, r, false)
}

func (s *HTTPServer) webDeleteOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	s.webMutateOrganizationInvitation(w, r, true)
}

func (s *HTTPServer) webMutateOrganizationInvitation(w http.ResponseWriter, r *http.Request, remove bool) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	mutate, resultKey := s.service.RevokeOrganizationInvitation, "revoked"
	if remove {
		mutate, resultKey = s.service.DeleteOrganizationInvitation, "deleted"
	}
	if err := mutate(
		r.Context(), *principal, r.PathValue("invitation_id"),
	); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]bool{resultKey: true})
}

func (s *HTTPServer) webPreviewOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.PreviewOrganizationInvitation(r.Context(), r.PathValue("token"))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func (s *HTTPServer) webAcceptOrganizationInvitation(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, err := s.webPrincipal(r)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	if principal != nil {
		if err := s.service.JoinOrganization(r.Context(), *principal, r.PathValue("token")); err != nil {
			s.writeServiceError(w, r, err)
			return
		}
		s.webStatus(w, r)
		return
	}
	var input authservice.AcceptOrganizationInvitationInput
	if !s.decode(w, r, &input) {
		return
	}
	input.Token = r.PathValue("token")
	if _, err := s.service.AcceptOrganizationInvitation(r.Context(), input); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	login, err := s.service.Login(r.Context(), authservice.LoginInput{
		Username: input.Username, Password: input.Password,
		ClientIP: webClientIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(login.SessionToken, false))
	s.writeWebStatus(w, r, &login.Principal)
}

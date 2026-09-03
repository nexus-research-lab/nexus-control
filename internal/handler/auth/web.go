package auth

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webStatus(w http.ResponseWriter, r *http.Request) {
	principal, err := s.webPrincipal(r)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeWebStatus(w, r, principal)
}

func (s *HTTPServer) webLogin(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	result, err := s.service.Login(r.Context(), authservice.LoginInput{
		Username: input.Username, Password: input.Password,
		ClientIP: webClientIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(result.SessionToken, false))
	s.writeWebStatus(w, r, &result.Principal)
}

func (s *HTTPServer) webLogout(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	if err := s.service.Logout(r.Context(), s.sessionToken(r)); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie("", true))
	s.writeWebStatus(w, r, nil)
}

func (s *HTTPServer) webSetup(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	if s.config.SetupToken == "" || !bearerMatches(r, s.config.SetupToken) {
		s.writeError(w, r, http.StatusUnauthorized, "setup_capability_invalid", "Setup capability 无效")
		return
	}
	var input authservice.SetupOwnerInput
	if !s.decode(w, r, &input) {
		return
	}
	if _, err := s.service.SetupOwner(r.Context(), input); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	result, err := s.service.Login(r.Context(), authservice.LoginInput{
		Username: input.Username, Password: input.Password,
		ClientIP: webClientIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	http.SetCookie(w, s.sessionCookie(result.SessionToken, false))
	s.writeWebStatus(w, r, &result.Principal)
}

func (s *HTTPServer) webUpdateProfile(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input struct {
		Avatar *string `json:"avatar"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	if input.Avatar == nil {
		s.writeServiceError(w, r, authservice.ErrRequestInvalid)
		return
	}
	user, err := s.service.UpdateAvatar(r.Context(), principal.UserID, *input.Avatar)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, user)
}

func (s *HTTPServer) webChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var payload passwordChangePayload
	if !s.decode(w, r, &payload) {
		return
	}
	input := authservice.ChangePasswordInput{
		UserID:          principal.UserID,
		RequestID:       payload.RequestID,
		CurrentPassword: payload.CurrentPassword,
		NewPassword:     payload.NewPassword,
	}
	user, err := s.service.ChangePassword(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, user)
}

func (s *HTTPServer) webPasswordReceipt(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	requestID := r.URL.Query().Get("request_id")
	outcome, err := s.service.PasswordChangeOutcome(r.Context(), principal.UserID, requestID)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]any{"request_id": requestID, "effect": outcome})
}

func (s *HTTPServer) webPasswordSettle(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input struct {
		RequestID string `json:"request_id"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	outcome, err := s.service.SettlePasswordChangeNotApplied(r.Context(), principal.UserID, input.RequestID)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]any{"request_id": input.RequestID, "effect": outcome})
}

func (s *HTTPServer) webMembers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	members, err := s.service.ListMembers(r.Context(), *principal)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, members)
}

func (s *HTTPServer) webCreateMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.CreateMemberInput
	if !s.decode(w, r, &input) {
		return
	}
	member, err := s.service.CreateMember(r.Context(), *principal, input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, member)
}

func (s *HTTPServer) webUpdateMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.UpdateMemberInput
	if !s.decode(w, r, &input) {
		return
	}
	member, err := s.service.UpdateMember(r.Context(), *principal, r.PathValue("user_id"), input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, member)
}

func (s *HTTPServer) writeWebStatus(w http.ResponseWriter, r *http.Request, principal *authservice.Principal) {
	state, err := s.service.State(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	payload := map[string]any{
		"auth_required": true, "password_login_enabled": state.PasswordLoginEnabled,
		"authenticated": principal != nil, "setup_required": state.SetupRequired,
		"setup_enabled": state.SetupEnabled,
		"username":      nil, "user_id": nil, "display_name": nil,
		"role": nil, "avatar": nil, "auth_method": nil,
	}
	if principal != nil {
		payload["username"] = principal.Username
		payload["user_id"] = principal.UserID
		payload["display_name"] = principal.DisplayName
		payload["role"] = principal.Role
		payload["avatar"] = principal.Avatar
		payload["auth_method"] = principal.AuthMethod
	}
	s.writeData(w, r, payload)
}

func (s *HTTPServer) requireWebPrincipal(w http.ResponseWriter, r *http.Request) (*authservice.Principal, bool) {
	principal, err := s.webPrincipal(r)
	if err != nil {
		s.writeServiceError(w, r, err)
		return nil, false
	}
	if principal == nil {
		s.writeServiceError(w, r, authservice.ErrUnauthenticated)
		return nil, false
	}
	return principal, true
}

func (s *HTTPServer) webPrincipal(r *http.Request) (*authservice.Principal, error) {
	return s.service.ResolveSession(r.Context(), s.sessionToken(r))
}

func (s *HTTPServer) sessionToken(r *http.Request) string {
	cookie, err := r.Cookie(s.config.SessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func (s *HTTPServer) sessionCookie(value string, clear bool) *http.Cookie {
	maxAge := int(s.config.SessionTTL.Seconds())
	expires := time.Time{}
	if clear {
		maxAge = -1
		expires = time.Unix(1, 0).UTC()
	}
	return &http.Cookie{
		Name: s.config.SessionCookieName, Value: value, Path: "/",
		MaxAge: maxAge, Expires: expires, HttpOnly: true,
		Secure: s.config.CookieSecure, SameSite: s.cookieSameSite(),
	}
}

func (s *HTTPServer) cookieSameSite() http.SameSite {
	switch s.config.CookieSameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func (s *HTTPServer) requireWebMutationOrigin(w http.ResponseWriter, r *http.Request) bool {
	if webOriginMatches(r) {
		return true
	}
	s.writeError(w, r, http.StatusForbidden, "origin_invalid", "请求来源无效")
	return false
}

func webOriginMatches(r *http.Request) bool {
	origin, err := url.Parse(strings.TrimSpace(r.Header.Get("Origin")))
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded != "" {
		scheme = strings.ToLower(forwarded)
	}
	return strings.EqualFold(origin.Scheme, scheme) && strings.EqualFold(origin.Host, r.Host)
}

func webClientIP(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
		return value
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

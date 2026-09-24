package auth

import (
	"net/http"
	"strings"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webNodes(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	result, err := s.service.ListNodes(r.Context(), *actor)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func (s *HTTPServer) webRegisterNode(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	actor, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.RegisterNodeInput
	if !s.decode(w, r, &input) {
		return
	}
	result, err := s.service.RegisterNode(r.Context(), *actor, input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func (s *HTTPServer) webNode(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	result, err := s.service.Node(r.Context(), *actor, r.PathValue("node_id"))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func (s *HTTPServer) webRevokeNode(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	actor, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	if err := s.service.RevokeNode(r.Context(), *actor, r.PathValue("node_id")); err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]bool{"revoked": true})
}

func (s *HTTPServer) nodeToken(w http.ResponseWriter, r *http.Request) {
	// 机器交换不使用 Cookie，不允许浏览器 Session 换取 Node audience。
	scheme, credential, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		s.writeServiceError(w, r, authservice.ErrUnauthenticated)
		return
	}
	var input struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if r.ContentLength != 0 && !s.decode(w, r, &input) {
		return
	}
	result, err := s.service.ExchangeNodeTokenWithDirectory(r.Context(), credential, input.AgentIDs)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

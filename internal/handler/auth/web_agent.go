package auth

import (
	"net/http"
	"strings"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webAgents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	agents, err := s.service.ListOwnedAgents(r.Context(), *principal)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, agents)
}

func (s *HTTPServer) webAgentDirectory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	agents, err := s.service.ListOrganizationAgents(r.Context(), *principal)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, agents)
}

func (s *HTTPServer) webPublishAgent(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.PublishAgentInput
	if !s.decode(w, r, &input) {
		return
	}
	sourceAgentID := strings.TrimSpace(r.PathValue("source_agent_id"))
	if sourceAgentID == "" || (input.SourceAgentID != "" && strings.TrimSpace(input.SourceAgentID) != sourceAgentID) {
		s.writeServiceError(w, r, authservice.ErrRequestInvalid)
		return
	}
	input.SourceAgentID = sourceAgentID
	agent, err := s.service.PublishAgent(r.Context(), *principal, input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, agent)
}

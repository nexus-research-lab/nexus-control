package auth

import (
	"net/http"
	"strings"

	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

func (s *HTTPServer) webSubscriptionOverview(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	overview, err := s.service.SubscriptionOverview(r.Context(), *principal)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, overview)
}

func (s *HTTPServer) webUpsertSubscriptionPlan(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.UpsertSubscriptionPlanInput
	if !s.decode(w, r, &input) {
		return
	}
	if planKey := strings.TrimSpace(r.PathValue("plan_key")); planKey != "" {
		input.PlanKey = planKey
	}
	overview, err := s.service.UpsertSubscriptionPlan(r.Context(), *principal, input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, overview)
}

func (s *HTTPServer) webUpdateMemberEntitlement(w http.ResponseWriter, r *http.Request) {
	if !s.requireWebMutationOrigin(w, r) {
		return
	}
	principal, ok := s.requireWebPrincipal(w, r)
	if !ok {
		return
	}
	var input authservice.UpdateMemberEntitlementInput
	if !s.decode(w, r, &input) {
		return
	}
	overview, err := s.service.UpdateMemberEntitlement(
		r.Context(),
		*principal,
		r.PathValue("user_id"),
		input,
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, overview)
}

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nexus-research-lab/nexus-control/internal/config"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
)

// HTTPServer 暴露 Control v1 API；internal 路由只接受服务凭据。
type HTTPServer struct {
	config  config.Config
	service *authservice.Service
	logger  *slog.Logger
	router  *http.ServeMux
}

type passwordChangePayload struct {
	RequestID       string `json:"request_id"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// NewHTTPServer 创建认证 HTTP handler。
func NewHTTPServer(cfg config.Config, service *authservice.Service, logger *slog.Logger) *HTTPServer {
	if logger == nil {
		logger = slog.Default()
	}
	server := &HTTPServer{config: cfg, service: service, logger: logger, router: http.NewServeMux()}
	server.mount()
	return server
}

// Handler 返回完整 HTTP handler。
func (s *HTTPServer) Handler() http.Handler {
	return s.requestContext(s.router)
}

func (s *HTTPServer) mount() {
	base := strings.TrimRight(s.config.APIBase, "/")
	webBase := strings.TrimRight(s.config.WebAuthBase, "/")
	s.router.HandleFunc("GET "+webBase+"/status", s.webStatus)
	s.router.HandleFunc("POST "+webBase+"/login", s.webLogin)
	s.router.HandleFunc("POST "+webBase+"/logout", s.webLogout)
	s.router.HandleFunc("POST "+webBase+"/setup", s.webSetup)
	s.router.HandleFunc("PATCH "+webBase+"/profile", s.webUpdateProfile)
	s.router.HandleFunc("POST "+webBase+"/profile/password", s.webChangePassword)
	s.router.HandleFunc("GET "+webBase+"/profile/password/receipt", s.webPasswordReceipt)
	s.router.HandleFunc("POST "+webBase+"/profile/password/receipt/not-applied", s.webPasswordSettle)
	s.router.HandleFunc("GET "+webBase+"/members", s.webMembers)
	s.router.HandleFunc("POST "+webBase+"/members", s.webCreateMember)
	s.router.HandleFunc("PATCH "+webBase+"/members/{user_id}", s.webUpdateMember)
	s.router.HandleFunc("GET "+webBase+"/subscription/overview", s.webSubscriptionOverview)
	s.router.HandleFunc("POST "+webBase+"/subscription/plans", s.webUpsertSubscriptionPlan)
	s.router.HandleFunc("PUT "+webBase+"/subscription/plans/{plan_key}", s.webUpsertSubscriptionPlan)
	s.router.HandleFunc("PUT "+webBase+"/subscription/users/{user_id}", s.webUpdateMemberEntitlement)
	s.router.HandleFunc("GET "+base+"/health", s.health)
	s.router.HandleFunc("GET "+base+"/.well-known/principal-key", s.publicKey)
	s.router.HandleFunc("POST "+base+"/setup/owner", s.setupOwner)
	internal := http.NewServeMux()
	internal.HandleFunc("GET "+base+"/internal/state", s.internalState)
	internal.HandleFunc("POST "+base+"/internal/principals/exchange", s.internalExchange)
	internal.HandleFunc("GET "+base+"/internal/identity-invalidations/latest", s.internalLatestIdentityInvalidation)
	internal.HandleFunc("GET "+base+"/internal/identity-invalidations", s.internalIdentityInvalidations)
	internal.HandleFunc("POST "+base+"/internal/humans/verify", s.internalVerifyHuman)
	internal.HandleFunc("GET "+base+"/internal/users/{user_id}/role", s.internalRole)
	internal.HandleFunc(
		"GET "+base+"/internal/deployments/{deployment_id}/users/{user_id}/entitlement",
		s.internalEntitlement,
	)
	s.router.Handle(base+"/internal/", s.requireService(internal))
}

func (s *HTTPServer) health(w http.ResponseWriter, r *http.Request) {
	if err := s.service.Health(r.Context()); err != nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "control_unavailable", "Control 数据库不可用")
		return
	}
	s.writeData(w, r, map[string]any{"status": "ok"})
}

func (s *HTTPServer) publicKey(w http.ResponseWriter, r *http.Request) {
	s.writeData(w, r, map[string]any{"algorithm": "Ed25519", "public_key": s.service.PublicKey()})
}

func (s *HTTPServer) setupOwner(w http.ResponseWriter, r *http.Request) {
	if s.config.SetupToken == "" || !bearerMatches(r, s.config.SetupToken) {
		s.writeError(w, r, http.StatusUnauthorized, "setup_capability_invalid", "Setup capability 无效")
		return
	}
	var input authservice.SetupOwnerInput
	if !s.decode(w, r, &input) {
		return
	}
	principal, err := s.service.SetupOwner(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, principal)
}

func (s *HTTPServer) internalState(w http.ResponseWriter, r *http.Request) {
	state, err := s.service.State(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, state)
}

func (s *HTTPServer) internalExchange(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionToken string `json:"session_token"`
		Audience     string `json:"audience"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	token, principal, err := s.service.ExchangePrincipal(r.Context(), input.SessionToken, input.Audience)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	state, err := s.service.State(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]any{"principal_token": token, "principal": principal, "state": state})
}

func (s *HTTPServer) internalLatestIdentityInvalidation(w http.ResponseWriter, r *http.Request) {
	cursor, err := s.service.LatestIdentityInvalidationID(r.Context())
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]int64{"cursor": cursor})
}

func (s *HTTPServer) internalIdentityInvalidations(w http.ResponseWriter, r *http.Request) {
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil || after < 0 {
		s.writeError(w, r, http.StatusBadRequest, "request_invalid", "after cursor 无效")
		return
	}
	limit := 256
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit <= 0 || limit > 256 {
			s.writeError(w, r, http.StatusBadRequest, "request_invalid", "limit 无效")
			return
		}
	}
	events, err := s.service.ListIdentityInvalidations(r.Context(), after, limit)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].EventID
	}
	s.writeData(w, r, map[string]any{"events": events, "next_cursor": next})
}

func (s *HTTPServer) internalVerifyHuman(w http.ResponseWriter, r *http.Request) {
	var input struct {
		UserID    string `json:"user_id"`
		SessionID string `json:"session_id"`
		Audience  string `json:"audience"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Audience) != strings.TrimSpace(s.config.PrincipalAudience) {
		s.writeError(w, r, http.StatusBadRequest, "principal_audience_invalid", "Principal audience 无效")
		return
	}
	token, err := s.service.ExchangeBoundHuman(r.Context(), input.UserID, input.SessionID, input.Audience)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]string{"principal_token": token})
}

func (s *HTTPServer) internalRole(w http.ResponseWriter, r *http.Request) {
	role, err := s.service.ActiveRole(r.Context(), r.PathValue("user_id"))
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, map[string]string{"role": role})
}

func (s *HTTPServer) internalEntitlement(w http.ResponseWriter, r *http.Request) {
	entitlement, err := s.service.EffectiveEntitlement(
		r.Context(),
		r.PathValue("deployment_id"),
		r.PathValue("user_id"),
	)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, entitlement)
}

func (s *HTTPServer) requireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bearerMatches(r, s.config.ServiceToken) {
			s.writeError(w, r, http.StatusUnauthorized, "service_credential_invalid", "服务凭据无效")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "request_invalid", "请求参数无效")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeError(w, r, http.StatusBadRequest, "request_invalid", "请求只能包含一个 JSON 值")
		return false
	}
	return true
}

func (s *HTTPServer) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := http.StatusInternalServerError, "control_internal", "Control 内部错误"
	switch {
	case errors.Is(err, authservice.ErrCurrentPassword):
		status, code, message = http.StatusUnprocessableEntity, "current_password_invalid", "当前密码不正确"
	case errors.Is(err, authservice.ErrInvalidCredentials):
		status, code, message = http.StatusUnauthorized, "credentials_invalid", "用户名或密码错误"
	case errors.Is(err, authservice.ErrUnauthenticated):
		status, code, message = http.StatusUnauthorized, "session_invalid", "登录状态无效或已过期"
	case errors.Is(err, authservice.ErrForbidden):
		status, code, message = http.StatusForbidden, "operation_forbidden", "没有权限执行此操作"
	case errors.Is(err, authservice.ErrAlreadySetup):
		status, code, message = http.StatusConflict, "setup_already_completed", err.Error()
	case errors.Is(err, authservice.ErrConflict):
		status, code, message = http.StatusConflict, "state_conflict", "当前状态不允许此操作"
	case errors.Is(err, authservice.ErrNotFound):
		status, code, message = http.StatusNotFound, "user_not_found", "用户不存在"
	case errors.Is(err, authservice.ErrPlanNotFound):
		status, code, message = http.StatusNotFound, "subscription_plan_not_found", "订阅套餐不存在或已归档"
	case errors.Is(err, authservice.ErrRequestInvalid):
		status, code, message = http.StatusBadRequest, "request_invalid", "请求参数无效"
	case errors.Is(err, authservice.ErrRequestNotApplied):
		status, code, message = http.StatusConflict, "password_change_not_applied", "密码没有修改"
	default:
		s.logger.Error("Control 请求失败", "request_id", requestID(r), "error", err)
	}
	s.writeError(w, r, status, code, message)
}

func (s *HTTPServer) writeData(w http.ResponseWriter, r *http.Request, data any) {
	s.writeJSON(w, http.StatusOK, map[string]any{"code": "0000", "message": "success", "request_id": requestID(r), "data": data})
}

func (s *HTTPServer) writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	category, effect := "internal", "unknown"
	if status < http.StatusInternalServerError {
		effect = "not_applied"
		switch status {
		case http.StatusUnauthorized:
			category = "authentication"
		case http.StatusForbidden:
			category = "authorization"
		case http.StatusBadRequest, http.StatusUnprocessableEntity:
			category = "validation"
		default:
			category = "conflict"
		}
	}
	s.writeJSON(w, status, map[string]any{
		"code": code, "message": message, "request_id": requestID(r),
		"data": map[string]any{"failure": map[string]any{
			"version": 1, "code": "control." + code, "category": category,
			"effect": effect, "transport_request_id": requestID(r),
		}},
		"details": map[string]any{},
	})
}

func (s *HTTPServer) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *HTTPServer) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := requestID(r)
		r.Header.Set("X-Request-ID", value)
		w.Header().Set("X-Request-ID", value)
		next.ServeHTTP(w, r)
	})
}

func bearerMatches(r *http.Request, expected string) bool {
	provided := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(provided) < 7 || !strings.EqualFold(provided[:7], "Bearer ") {
		return false
	}
	provided = strings.TrimSpace(provided[7:])
	return len(provided) == len(expected) && subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func requestID(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if value != "" && len(value) <= 128 {
		return value
	}
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err == nil {
		return "req_" + hex.EncodeToString(buffer)
	}
	return "req_" + time.Now().UTC().Format("20060102150405.000000000")
}

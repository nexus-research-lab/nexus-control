// INPUT: 服务凭据、宿主绑定的真人 Session 与成员操作。
// OUTPUT: 经当前部署管理员权限复核的成员读取与变更。
// POS: Agent 管理成员的 Control 内部入口；角色与部署不得由请求声明。
package auth

import (
	"bytes"
	"encoding/json"
	authservice "github.com/nexus-research-lab/nexus-control/internal/service/auth"
	"net/http"
)

func (s *HTTPServer) internalManageMembers(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ActorUserID     string          `json:"actor_user_id"`
		SessionID       string          `json:"session_id"`
		Operation       string          `json:"operation"`
		Target          string          `json:"target"`
		ExpectedVersion int64           `json:"expected_version"`
		Input           json.RawMessage `json:"input"`
	}
	if !s.decode(w, r, &input) {
		return
	}
	principal, err := s.service.VerifyBoundHuman(r.Context(), input.ActorUserID, input.SessionID)
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	var result any
	switch input.Operation {
	case "list":
		result, err = s.service.ListMembers(r.Context(), *principal)
	case "create":
		var value authservice.CreateMemberInput
		if err = decodeManagedMemberInput(input.Input, &value); err == nil {
			result, err = s.service.CreateMember(r.Context(), *principal, value)
		}
	case "update", "remove":
		var value authservice.UpdateMemberInput
		if input.ExpectedVersion <= 0 {
			err = authservice.ErrRequestInvalid
			break
		}
		if input.Operation == "remove" {
			status := "revoked"
			value.Status = &status
		} else if err = decodeManagedMemberInput(input.Input, &value); err != nil {
			break
		}
		value.ExpectedVersion = &input.ExpectedVersion
		result, err = s.service.UpdateMember(r.Context(), *principal, input.Target, value)
	default:
		err = authservice.ErrRequestInvalid
	}
	if err != nil {
		s.writeServiceError(w, r, err)
		return
	}
	s.writeData(w, r, result)
}

func decodeManagedMemberInput(input json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return authservice.ErrRequestInvalid
	}
	return nil
}

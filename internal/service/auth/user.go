package auth

import (
	"context"
	"errors"
	"strings"

	store "github.com/nexus-research-lab/nexus-control/internal/storage/auth"
)

// ChangePassword 以 request_id 提供持久幂等的密码修改。
func (s *Service) ChangePassword(ctx context.Context, input ChangePasswordInput) (*User, error) {
	userID := strings.TrimSpace(input.UserID)
	requestID, err := normalizeRequestID(input.RequestID)
	if userID == "" || err != nil {
		return nil, errors.Join(ErrRequestInvalid, err)
	}
	if outcome, outcomeErr := s.PasswordChangeOutcome(ctx, userID, requestID); outcomeErr != nil {
		return nil, outcomeErr
	} else if outcome == PasswordChangeCommitted {
		return s.UserByID(ctx, userID)
	} else if outcome == PasswordChangeNotApplied {
		return nil, ErrRequestNotApplied
	}
	if strings.TrimSpace(input.CurrentPassword) == "" || validatePassword(input.NewPassword) != nil {
		return s.rejectPasswordChange(ctx, userID, requestID, ErrRequestInvalid)
	}
	currentHash, status, err := s.repository.PasswordCredential(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return s.rejectPasswordChange(ctx, userID, requestID, ErrCurrentPassword)
	}
	if err != nil {
		return nil, err
	}
	matched, verifyErr := verifyPassword(input.CurrentPassword, currentHash)
	if verifyErr != nil || !matched || status != StatusActive {
		return s.rejectPasswordChange(ctx, userID, requestID, ErrCurrentPassword)
	}
	nextHash, err := hashPassword(input.NewPassword)
	if err != nil {
		return s.rejectPasswordChange(ctx, userID, requestID, err)
	}
	attempt, err := s.repository.TryCommitPasswordChange(ctx, userID, requestID, currentHash, nextHash, s.now())
	if err != nil {
		return nil, err
	}
	switch attempt {
	case store.PasswordAttemptCommitted:
		return s.UserByID(ctx, userID)
	case store.PasswordAttemptExisting:
		return s.resolvePasswordChange(ctx, userID, requestID)
	default:
		return s.rejectPasswordChange(ctx, userID, requestID, ErrCurrentPassword)
	}
}

func (s *Service) rejectPasswordChange(ctx context.Context, userID, requestID string, rejection error) (*User, error) {
	if err := s.settlePasswordChange(ctx, userID, requestID, PasswordChangeNotApplied); err != nil {
		return nil, err
	}
	user, err := s.resolvePasswordChange(ctx, userID, requestID)
	if errors.Is(err, ErrRequestNotApplied) {
		return nil, rejection
	}
	return user, err
}

func (s *Service) resolvePasswordChange(ctx context.Context, userID, requestID string) (*User, error) {
	outcome, err := s.PasswordChangeOutcome(ctx, userID, requestID)
	if err != nil {
		return nil, err
	}
	switch outcome {
	case PasswordChangeCommitted:
		return s.UserByID(ctx, userID)
	case PasswordChangeNotApplied:
		return nil, ErrRequestNotApplied
	default:
		return nil, errors.New("password request 没有持久终态")
	}
}

// PasswordChangeOutcome 返回密码修改请求的持久终态。
func (s *Service) PasswordChangeOutcome(ctx context.Context, userID, requestID string) (PasswordChangeOutcome, error) {
	requestID, err := normalizeRequestID(requestID)
	if err != nil {
		return PasswordChangeUnknown, errors.Join(ErrRequestInvalid, err)
	}
	outcome, err := s.repository.PasswordChangeOutcome(ctx, strings.TrimSpace(userID), requestID)
	if err != nil || outcome != "" {
		return PasswordChangeOutcome(outcome), err
	}
	return PasswordChangeUnknown, nil
}

// SettlePasswordChangeNotApplied 将无法确认提交的请求收敛为未应用。
func (s *Service) SettlePasswordChangeNotApplied(ctx context.Context, userID, requestID string) (PasswordChangeOutcome, error) {
	requestID, err := normalizeRequestID(requestID)
	if err != nil {
		return PasswordChangeUnknown, errors.Join(ErrRequestInvalid, err)
	}
	if err = s.settlePasswordChange(ctx, strings.TrimSpace(userID), requestID, PasswordChangeNotApplied); err != nil {
		return PasswordChangeUnknown, err
	}
	return s.PasswordChangeOutcome(ctx, userID, requestID)
}

func (s *Service) settlePasswordChange(ctx context.Context, userID, requestID string, outcome PasswordChangeOutcome) error {
	return s.repository.SettlePasswordChange(ctx, userID, requestID, string(outcome), s.now())
}

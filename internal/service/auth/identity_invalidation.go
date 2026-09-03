package auth

import "context"

const maxIdentityInvalidationBatch = 256

// LatestIdentityInvalidationID 返回当前失效序列游标。
func (s *Service) LatestIdentityInvalidationID(ctx context.Context) (int64, error) {
	return s.repository.LatestIdentityInvalidationID(ctx)
}

// ListIdentityInvalidations 按事件顺序返回游标之后的身份变更。
func (s *Service) ListIdentityInvalidations(
	ctx context.Context,
	after int64,
	limit int,
) ([]IdentityInvalidation, error) {
	if after < 0 {
		after = 0
	}
	if limit <= 0 || limit > maxIdentityInvalidationBatch {
		limit = maxIdentityInvalidationBatch
	}
	records, err := s.repository.ListIdentityInvalidations(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	events := make([]IdentityInvalidation, 0, len(records))
	for _, record := range records {
		events = append(events, IdentityInvalidation{
			EventID: record.EventID, DeploymentID: record.DeploymentID,
			UserID: record.UserID, SessionID: record.SessionID,
			Reason: record.Reason, CreatedAt: record.CreatedAt,
		})
	}
	return events, nil
}

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxPasswordLength = 1024

func normalizeUsername(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 64 {
		return "", errors.New("用户名长度必须在 3 到 64 个字符之间")
	}
	for _, item := range value {
		if (item >= 'a' && item <= 'z') || (item >= '0' && item <= '9') || strings.ContainsRune("-_.", item) {
			continue
		}
		return "", errors.New("用户名只能包含小写字母、数字、点、横线和下划线")
	}
	return value, nil
}

func validatePassword(value string) error {
	if len(value) < 8 {
		return errors.New("密码长度至少需要 8 个字符")
	}
	if len(value) > maxPasswordLength {
		return errors.New("密码长度不能超过 1024 个字节")
	}
	return nil
}

func normalizeRole(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", RoleMember:
		return RoleMember, nil
	case RoleOwner, RoleAdmin:
		return strings.TrimSpace(value), nil
	default:
		return "", errors.New("role 仅支持 owner、admin、member")
	}
}

func normalizeRequestID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 8 || len(value) > 128 {
		return "", errors.New("request_id 长度必须在 8 到 128 个字符之间")
	}
	for _, item := range value {
		if (item >= 'a' && item <= 'z') || (item >= 'A' && item <= 'Z') || (item >= '0' && item <= '9') || strings.ContainsRune("._:-", item) {
			continue
		}
		return "", errors.New("request_id 包含非法字符")
	}
	return value, nil
}

func newID(prefix string) string {
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(buffer)
}

func newToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func hashToken(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(digest[:])
}

package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const principalTokenHeader = `{"alg":"EdDSA","typ":"NEXUS-PRINCIPAL","v":1}`

// Signer 持有 Control 私钥；下游服务只配置对应公钥。
type Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// LoadSigner 加载显式私钥，或以 owner-only 权限生成持久密钥对。
func LoadSigner(encodedPrivateKey, privateKeyPath, publicKeyPath string) (*Signer, error) {
	encodedPrivateKey = strings.TrimSpace(encodedPrivateKey)
	if encodedPrivateKey == "" {
		data, err := os.ReadFile(privateKeyPath)
		if err == nil {
			encodedPrivateKey = strings.TrimSpace(string(data))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if encodedPrivateKey == "" {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		encodedPrivateKey = base64.RawStdEncoding.EncodeToString(privateKey)
		if err = writeSecret(privateKeyPath, encodedPrivateKey); err != nil {
			return nil, err
		}
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(encodedPrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("Control Ed25519 私钥无效")
	}
	publicKey := ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
	if publicKeyPath != "" {
		if err = writePublic(publicKeyPath, base64.RawStdEncoding.EncodeToString(publicKey)); err != nil {
			return nil, err
		}
	}
	return &Signer{privateKey: ed25519.PrivateKey(privateKey), publicKey: publicKey}, nil
}

func (s *Signer) Sign(principal Principal, audience string, now time.Time, ttl time.Duration) (string, error) {
	claims := PrincipalClaims{
		Version: 1, Issuer: "nexus-control", Audience: audience,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
		DeploymentID: principal.DeploymentID, UserID: principal.UserID,
		Username: principal.Username, DisplayName: principal.DisplayName,
		Role: principal.Role, Avatar: principal.Avatar,
		AuthMethod: principal.AuthMethod, SessionID: principal.SessionID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(principalTokenHeader))
	body := base64.RawURLEncoding.EncodeToString(payload)
	signed := header + "." + body
	signature := ed25519.Sign(s.privateKey, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Signer) PublicKey() string {
	return base64.RawStdEncoding.EncodeToString(s.publicKey)
}

func writeSecret(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}

func writePublic(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}

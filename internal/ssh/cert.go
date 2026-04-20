package sshcert

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mastervolkov/opkssh-oidc/internal/oidc"
	"golang.org/x/crypto/ssh"
)

type VerifyResult struct {
	Username string
	Groups   []string
	Sudo     bool
}

// EnsureUserKeyPair generates an ed25519 SSH keypair if it doesn't exist.
func EnsureUserKeyPair(username, privPath string) error {
	if _, err := os.Stat(privPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privPath, "-N", "", "-q", "-C", fmt.Sprintf("%s@qwe", username))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ComputeNonce computes base64url(SHA256(pubkey_bytes)) for PK Token binding.
func ComputeNonce(pubKeyPath string) (string, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return "", err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(pubKey.Marshal())
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// CreateSelfSignedCert creates an SSH certificate signed by the user's own key (PK Token style).
// The OIDC token is embedded in KeyId as "username|jwt".
// No separate CA — the user's private key acts as its own CA.
func CreateSelfSignedCert(username, idToken, privKeyPath, certPath string) error {
	privBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(privBytes)
	if err != nil {
		return err
	}

	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           username + "|" + idToken,
		ValidPrincipals: []string{username},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(15 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return err
	}

	data := ssh.MarshalAuthorizedKey(cert)
	return os.WriteFile(certPath, data, 0o644)
}

// VerifyPKToken verifies a PK Token: checks OIDC token signature and nonce binding.
// Returns VerifyResult if the token is valid and bound to the cert's key.
func VerifyPKToken(cert *ssh.Certificate, apiURL string) (*VerifyResult, error) {
	// Extract OIDC token from KeyId
	parts := strings.SplitN(cert.KeyId, "|", 2)
	if len(parts) != 2 {
		return nil, errors.New("no OIDC token in certificate KeyId")
	}
	idToken := parts[1]

	// Verify OIDC token signature via JWKS
	claims, err := oidc.ParseAndVerifyIDToken(apiURL, idToken)
	if err != nil {
		return nil, fmt.Errorf("OIDC token verification failed: %w", err)
	}

	// Verify nonce binding: nonce must equal base64url(SHA256(cert public key))
	hash := sha256.Sum256(cert.Key.Marshal())
	expectedNonce := base64.RawURLEncoding.EncodeToString(hash[:])
	if claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("nonce mismatch: token nonce does not match certificate public key")
	}

	// Check cert time validity
	now := time.Now().Unix()
	if now < int64(cert.ValidAfter) || now > int64(cert.ValidBefore) {
		return nil, errors.New("certificate is expired or not yet valid")
	}

	return &VerifyResult{
		Username: claims.Subject,
		Groups:   claims.Groups,
		Sudo:     HasSudo(claims.Groups),
	}, nil
}

// ParseAuthorizedKey wraps ssh.ParseAuthorizedKey.
func ParseAuthorizedKey(in []byte) (ssh.PublicKey, string, []string, []byte, error) {
	return ssh.ParseAuthorizedKey(in)
}

// AsCertificate tries to cast a PublicKey to *ssh.Certificate.
func AsCertificate(key ssh.PublicKey) (*ssh.Certificate, bool) {
	cert, ok := key.(*ssh.Certificate)
	return cert, ok
}

// MarshalPublicKey formats a public key as an authorized_keys line.
func MarshalPublicKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// HasSudo checks if any group implies sudo access.
func HasSudo(groups []string) bool {
	for _, g := range groups {
		if strings.Contains(g, "admin") || strings.Contains(g, "sudo") {
			return true
		}
	}
	return false
}

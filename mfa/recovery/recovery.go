// Package recovery is the backup/recovery-code MFA driver: single-use codes that unlock an
// account when the primary factor is lost.
//
// Import it for its side effect of registering the "recovery" driver:
//
//	import _ "azugo.io/auth/mfa/recovery"
package recovery

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"azugo.io/core/password"
	"github.com/goccy/go-json"
)

// DriverName is the registered driver name.
const DriverName = "recovery"

// alphabet excludes visually ambiguous characters.
const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"

var codeHasher = password.NewArgon2id()

// codeSeparators are the characters a user may type between code groups.
var codeSeparators = strings.NewReplacer("-", "", " ", "")

func init() {
	mfa.Register(DriverName, driver{})
}

type driver struct{}

// Open creates the recovery-code method. Config keys: count (codes per set, default 10),
// length (characters per code, default 10).
func (driver) Open(store mfa.Store, cfg *contract.MFAMethodConfig) (mfa.Method, error) {
	m := &method{store: store, name: cfg.Name, count: 10, length: 10}

	if v := cfg.Config["count"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("recovery: invalid count %q", v)
		}

		m.count = n
	}

	if v := cfg.Config["length"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 6 {
			return nil, fmt.Errorf("recovery: invalid length %q (minimum 6)", v)
		}

		m.length = n
	}

	return m, nil
}

type method struct {
	store  mfa.Store
	name   string
	count  int
	length int
}

// BeginEnroll generates a fresh code set; the plain codes are shown once, only hashes are kept.
func (m *method) BeginEnroll(context.Context, string, contract.UserInfo) (mfa.EnrollmentData, error) {
	codes := make([]string, m.count)
	hashes := make([]string, m.count)

	for i := range codes {
		code, err := m.generate()
		if err != nil {
			return mfa.EnrollmentData{}, err
		}

		hash, err := codeHasher.Hash(normalize(code))
		if err != nil {
			return mfa.EnrollmentData{}, err
		}

		codes[i] = code
		hashes[i] = hash
	}

	state, err := json.Marshal(hashes)
	if err != nil {
		return mfa.EnrollmentData{}, err
	}

	return mfa.EnrollmentData{Data: map[string]any{"codes": codes}, State: state}, nil
}

// FinishEnroll returns the generated set as the secret; there is nothing for the user to prove.
func (m *method) FinishEnroll(_ context.Context, _ string, state []byte, _ map[string]any) ([]byte, error) {
	if len(state) == 0 {
		return nil, mfa.ErrInvalidResponse
	}

	return state, nil
}

// Exclusive marks the code set as the user's only enrollment; revoke it to regenerate.
func (m *method) Exclusive() bool {
	return true
}

// Backup marks the codes as a fallback for another factor, never the first one.
func (m *method) Backup() bool {
	return true
}

// BeginVerify is a no-op: recovery codes are self-contained.
func (m *method) BeginVerify(context.Context, string) (string, map[string]any, error) {
	return "", nil, nil
}

// Verify consumes the submitted code when it matches an unused one.
func (m *method) Verify(ctx context.Context, userID, _ string, response map[string]any) (mfa.Verification, error) {
	code, _ := response["code"].(string)

	code = normalize(code)
	if code == "" {
		return mfa.Verification{Result: mfa.VerifyDenied}, nil
	}

	for range 3 {
		enrollments, err := mfa.Enrolled(ctx, m.store, userID, m.name)
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		if len(enrollments) == 0 {
			return mfa.Verification{Result: mfa.VerifyDenied}, mfa.ErrNotEnrolled
		}

		set := enrollments[0]

		var hashes []string
		if err := json.Unmarshal(set.Secret, &hashes); err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		match := -1

		for i, hash := range hashes {
			ok, err := codeHasher.Verify(code, hash)
			if err != nil {
				return mfa.Verification{Result: mfa.VerifyDenied}, fmt.Errorf("recovery: verify code: %w", err)
			}

			if ok {
				match = i
			}
		}

		if match < 0 {
			return mfa.Verification{Result: mfa.VerifyDenied}, nil
		}

		remaining, err := json.Marshal(append(hashes[:match], hashes[match+1:]...))
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		swapped, err := m.store.CompareAndSwap(ctx, userID, set.ID, set.Secret, remaining)
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		if swapped {
			return mfa.Verification{Result: mfa.VerifyApproved, EnrollmentID: set.ID}, nil
		}
	}

	return mfa.Verification{Result: mfa.VerifyDenied}, nil
}

// generate returns one random code formatted in dash-separated groups of five.
func (m *method) generate() (string, error) {
	var b strings.Builder

	buf := make([]byte, 1)

	for i := 0; i < m.length; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}

		if int(buf[0]) >= 256-256%len(alphabet) {
			continue
		}

		if i > 0 && i%5 == 0 {
			b.WriteByte('-')
		}

		b.WriteByte(alphabet[int(buf[0])%len(alphabet)])
		i++
	}

	return b.String(), nil
}

// normalize strips separators and case so a user may type the code however it was shown.
func normalize(code string) string {
	return codeSeparators.Replace(strings.ToLower(strings.TrimSpace(code)))
}

var _ interface {
	mfa.Method
	mfa.ExclusiveMethod
	mfa.BackupMethod
} = (*method)(nil)

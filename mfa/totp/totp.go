// Package totp is the built-in RFC 6238 time-based one-time password MFA driver.
//
// Import it for its side effect of registering the "totp" driver:
//
//	import _ "azugo.io/auth/mfa/totp"
package totp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"azugo.io/auth/contract"
	"azugo.io/auth/mfa"

	"github.com/goccy/go-json"
	"github.com/lafriks/otp"
	"github.com/lafriks/otp/totp"
)

// DriverName is the registered driver name.
const DriverName = "totp"

func init() {
	mfa.Register(DriverName, driver{})
}

type driver struct{}

// Open creates the TOTP method. Config keys: issuer (default "azugo"), digits (6|8, default 6),
// period (seconds, default 30), algorithm (SHA1|SHA256|SHA512, default SHA1), skew (periods of
// leeway, default 1).
func (driver) Open(store mfa.Store, cfg *contract.MFAMethodConfig) (mfa.Method, error) {
	m := &method{
		store:  store,
		name:   cfg.Name,
		issuer: "azugo",
		opts:   totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1},
		period: 30,
		skew:   1,
	}

	if v := cfg.Config["issuer"]; v != "" {
		m.issuer = v
	}

	if v := cfg.Config["digits"]; v != "" {
		switch v {
		case "6":
			m.opts.Digits = otp.DigitsSix
		case "8":
			m.opts.Digits = otp.DigitsEight
		default:
			return nil, fmt.Errorf("totp: digits must be 6 or 8, got %q", v)
		}
	}

	if v := cfg.Config["period"]; v != "" {
		p, err := strconv.ParseUint(v, 10, 32)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("totp: invalid period %q", v)
		}

		m.opts.Period = uint(p)
		m.period = int64(p)
	}

	if v := cfg.Config["algorithm"]; v != "" {
		switch strings.ToUpper(v) {
		case "SHA1":
			m.opts.Algorithm = otp.AlgorithmSHA1
		case "SHA256":
			m.opts.Algorithm = otp.AlgorithmSHA256
		case "SHA512":
			m.opts.Algorithm = otp.AlgorithmSHA512
		default:
			return nil, fmt.Errorf("totp: unsupported algorithm %q", v)
		}
	}

	if v := cfg.Config["skew"]; v != "" {
		s, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("totp: invalid skew %q", v)
		}

		m.opts.Skew = uint(s)
		m.skew = int64(s)
	}

	return m, nil
}

type method struct {
	store  mfa.Store
	name   string
	issuer string
	opts   totp.ValidateOpts
	// period and skew mirror opts for time-step arithmetic.
	period int64
	skew   int64
}

// secret is the stored enrollment: the base32 seed and the last accepted time step, so a code
// cannot be replayed within its validity window.
type secret struct {
	Seed string `json:"seed"`
	Last int64  `json:"last,omitempty"`
}

// BeginEnroll generates a fresh seed, returning the otpauth URI and secret for the client.
func (m *method) BeginEnroll(_ context.Context, userID string, info contract.UserInfo) (mfa.EnrollmentData, error) {
	account := info.Email
	if account == "" {
		account = info.Name
	}

	if account == "" {
		account = userID
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: account,
		Period:      m.opts.Period,
		Digits:      m.opts.Digits,
		Algorithm:   m.opts.Algorithm,
	})
	if err != nil {
		return mfa.EnrollmentData{}, err
	}

	return mfa.EnrollmentData{
		Data: map[string]any{
			"secret":    key.Secret(),
			"uri":       key.URL(),
			"issuer":    m.issuer,
			"account":   account,
			"digits":    m.opts.Digits.Length(),
			"period":    m.opts.Period,
			"algorithm": m.opts.Algorithm.String(),
		},
		State: []byte(key.Secret()),
	}, nil
}

// FinishEnroll verifies the first code against the pending seed and returns the enrollment
// secret.
func (m *method) FinishEnroll(_ context.Context, _ string, state []byte, response map[string]any) ([]byte, error) {
	if len(state) == 0 {
		return nil, mfa.ErrInvalidResponse
	}

	step, ok := m.validate(string(state), response, 0)
	if !ok {
		return nil, mfa.ErrInvalidResponse
	}

	return json.Marshal(secret{Seed: string(state), Last: step})
}

// BeginVerify is a no-op: TOTP is self-contained.
func (m *method) BeginVerify(context.Context, string) (string, map[string]any, error) {
	return "", nil, nil
}

// Verify checks the submitted code against every enrolled seed.
func (m *method) Verify(ctx context.Context, userID, _ string, response map[string]any) (mfa.Verification, error) {
	for range 3 {
		enrollments, err := mfa.Enrolled(ctx, m.store, userID, m.name)
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		if len(enrollments) == 0 {
			return mfa.Verification{Result: mfa.VerifyDenied}, mfa.ErrNotEnrolled
		}

		var matched *mfa.Enrollment

		var s secret

		for _, e := range enrollments {
			if err := json.Unmarshal(e.Secret, &s); err != nil {
				return mfa.Verification{Result: mfa.VerifyDenied}, err
			}

			if step, ok := m.validate(s.Seed, response, s.Last); ok {
				s.Last = step
				matched = e

				break
			}
		}

		if matched == nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, nil
		}

		updated, err := json.Marshal(s)
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		swapped, err := m.store.CompareAndSwap(ctx, userID, matched.ID, matched.Secret, updated)
		if err != nil {
			return mfa.Verification{Result: mfa.VerifyDenied}, err
		}

		if swapped {
			return mfa.Verification{Result: mfa.VerifyApproved, EnrollmentID: matched.ID}, nil
		}
	}

	return mfa.Verification{Result: mfa.VerifyDenied}, nil
}

// AMR reports the RFC 8176 values for a passed TOTP factor.
func (m *method) AMR() []string {
	return []string{"otp", "mfa"}
}

// validate checks the code in response against seed and returns the matched time step, which
// must be newer than last.
func (m *method) validate(seed string, response map[string]any, last int64) (int64, bool) {
	code, _ := response["code"].(string)
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")

	if len(code) != m.opts.Digits.Length() {
		return 0, false
	}

	now := time.Now()

	for delta := -m.skew; delta <= m.skew; delta++ {
		at := now.Add(time.Duration(delta*m.period) * time.Second)

		step := at.Unix() / m.period
		if step <= last {
			continue
		}

		exact := m.opts
		exact.Skew = 0

		if ok, err := totp.ValidateCustom(code, seed, at, exact); err == nil && ok {
			return step, true
		}
	}

	return 0, false
}

var _ interface {
	mfa.Method
	mfa.AMRProvider
} = (*method)(nil)

// ErrNotEnrolled is re-exported for callers matching a missing enrollment.
var ErrNotEnrolled = mfa.ErrNotEnrolled

// GenerateCode returns the current code for seed, for tests and tooling.
func GenerateCode(seed string, at time.Time) (string, error) {
	if seed == "" {
		return "", errors.New("totp: empty seed")
	}

	return totp.GenerateCode(seed, at)
}

package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
)

type stubProvider struct {
	cfg    *contract.ExternalProviderConfig
	logout bool
}

func (p *stubProvider) AuthURL(_ context.Context, state, _, _ string) (string, error) {
	return "https://idp.example/auth?state=" + state, nil
}

func (p *stubProvider) Exchange(context.Context, string, string, string) (*Tokens, error) {
	return &Tokens{RawClaims: map[string]any{"sub": "s1"}}, nil
}

type stubLogoutProvider struct {
	stubProvider
}

func (p *stubLogoutProvider) LogoutURL(_ context.Context, _, state, _ string) (string, error) {
	return "https://idp.example/logout?state=" + state, nil
}

type stubDriver struct {
	logout bool
	opened int
}

func (d *stubDriver) Open(cfg *contract.ExternalProviderConfig) (Provider, error) {
	d.opened++

	if d.logout {
		return &stubLogoutProvider{stubProvider{cfg: cfg, logout: true}}, nil
	}

	return &stubProvider{cfg: cfg}, nil
}

func (d *stubDriver) DefaultClaimMapper() ClaimMapper {
	return ClaimMapperFunc(MapStandardClaims)
}

var (
	testDriver       = &stubDriver{}
	testLogoutDriver = &stubDriver{logout: true}
)

func init() {
	Register("stub", testDriver)
	Register("stublogout", testLogoutDriver)
}

func TestRegisterPanicsOnDuplicateAndNil(t *testing.T) {
	qt.Check(t, qt.PanicMatches(func() { Register("stub", testDriver) }, ".*called twice.*"))
	qt.Check(t, qt.PanicMatches(func() { Register("nil", nil) }, ".*driver is nil.*"))
}

func TestDefaultClaimMapperUnknownDriver(t *testing.T) {
	_, err := DefaultClaimMapper("missing")
	qt.Check(t, qt.ErrorMatches(err, ".*unknown driver.*"))

	m, err := DefaultClaimMapper("stub")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsNotNil(m))
}

func TestConfigRegistryResolvesAndCaches(t *testing.T) {
	before := testDriver.opened
	cfg := &contract.Configuration{Providers: []contract.ExternalProviderConfig{
		{Name: "corp", Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb"},
	}}
	r := NewConfigRegistry(cfg)

	p1, entry, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(entry.ClientID, "c1"))

	p2, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(p1, p2))
	qt.Check(t, qt.Equals(testDriver.opened, before+1))

	// A changed behaviour-affecting field transparently re-opens.
	cfg.Providers[0].ClientSecret = "rotated"

	p3, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(p1 != p3))
	qt.Check(t, qt.Equals(testDriver.opened, before+2))
}

func TestConfigRegistryDetectsInPlaceConfigEdit(t *testing.T) {
	cfg := &contract.Configuration{Providers: []contract.ExternalProviderConfig{
		{
			Name: "corp", Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb",
			Scopes: []string{"openid"}, Config: map[string]string{"tenant": "a"},
		},
	}}
	r := NewConfigRegistry(cfg)

	p1, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))

	// Editing the live map in place, without replacing it, still re-opens.
	cfg.Providers[0].Config["tenant"] = "b"

	p2, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(p1 != p2))

	cfg.Providers[0].Scopes[0] = "profile"

	p3, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(p2 != p3))
}

func TestConfigRegistryClockSkewInheritsAndOverrides(t *testing.T) {
	wide, strict := 4*time.Minute, time.Duration(0)
	cfg := &contract.Configuration{
		ClockSkew: time.Minute,
		Providers: []contract.ExternalProviderConfig{
			{Name: "corp", Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb"},
			{Name: "slow", Driver: "stub", ClientID: "c2", RedirectURL: "https://app.example/cb", ClockSkew: &wide},
			{Name: "exact", Driver: "stub", ClientID: "c3", RedirectURL: "https://app.example/cb", ClockSkew: &strict},
		},
	}
	r := NewConfigRegistry(cfg)

	p, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(p.(*stubProvider).cfg.EffectiveClockSkew(), time.Minute))

	// A per-provider value wins over the app-wide one.
	p2, _, err := r.Get(context.Background(), "slow")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(p2.(*stubProvider).cfg.EffectiveClockSkew(), 4*time.Minute))

	// An explicit zero pins strict validation instead of inheriting.
	p3, _, err := r.Get(context.Background(), "exact")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(p3.(*stubProvider).cfg.EffectiveClockSkew(), time.Duration(0)))

	// Changing the app-wide value re-opens the inheriting provider.
	cfg.ClockSkew = 2 * time.Minute

	p4, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(p != p4))
	qt.Check(t, qt.Equals(p4.(*stubProvider).cfg.EffectiveClockSkew(), 2*time.Minute))
}

func TestConfigRegistryUnknownName(t *testing.T) {
	r := NewConfigRegistry(&contract.Configuration{})

	_, _, err := r.Get(context.Background(), "nope")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrNotFound)))
}

func TestConfigRegistryNameFallsBackToDriver(t *testing.T) {
	r := NewConfigRegistry(&contract.Configuration{Providers: []contract.ExternalProviderConfig{
		{Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb"},
	}})

	_, entry, err := r.Get(context.Background(), "stub")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(entry.Driver, "stub"))
}

func TestConfigRegistryEnforcesLogoutAfterAuth(t *testing.T) {
	r := NewConfigRegistry(&contract.Configuration{Providers: []contract.ExternalProviderConfig{
		{Name: "nosso", Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb", LogoutAfterAuth: true},
		{Name: "ok", Driver: "stublogout", ClientID: "c1", RedirectURL: "https://app.example/cb", LogoutAfterAuth: true},
	}})

	_, _, err := r.Get(context.Background(), "nosso")
	qt.Check(t, qt.ErrorMatches(err, ".*requires driver.*RP-initiated logout.*"))

	_, _, err = r.Get(context.Background(), "ok")
	qt.Check(t, qt.IsNil(err))
}

func TestConfigRegistryPrewarm(t *testing.T) {
	before := testDriver.opened
	r := NewConfigRegistry(&contract.Configuration{Providers: []contract.ExternalProviderConfig{
		{Name: "corp", Driver: "stub", ClientID: "c1", RedirectURL: "https://app.example/cb"},
	}})

	pw, ok := r.(Prewarmer)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsNil(pw.Prewarm(context.Background())))
	qt.Check(t, qt.Equals(testDriver.opened, before+1))

	// The pre-warmed instance is reused.
	_, _, err := r.Get(context.Background(), "corp")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(testDriver.opened, before+1))
}

func TestMapStandardClaims(t *testing.T) {
	info, err := MapStandardClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "name": "Alice", "email": "alice@example.com",
		"scp":    "openid profile",
		"groups": []any{"admins", "users"},
		"dept":   "R&D",
		"iss":    "https://idp.example", "exp": 123, "nonce": "n",
	})
	qt.Assert(t, qt.IsNil(err))

	qt.Check(t, qt.Equals(info.ID, "s1"))
	qt.Check(t, qt.Equals(info.Name, "Alice"))
	qt.Check(t, qt.Equals(info.Email, "alice@example.com"))
	qt.Check(t, qt.StringContains(info.Scope, "openid"))
	qt.Check(t, qt.StringContains(info.Scope, "admins"))
	qt.Check(t, qt.Equals(info.Claims["dept"], "R&D"))

	// Protocol claims are dropped.
	_, hasIss := info.Claims["iss"]
	qt.Check(t, qt.IsFalse(hasIss))
}

func TestMapStandardClaimsGivenFamilyNameAndMissingSub(t *testing.T) {
	info, err := MapStandardClaims(context.Background(), "corp", map[string]any{
		"sub": "s1", "given_name": "Alice", "family_name": "Doe",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(info.Name, "Alice Doe"))

	_, err = MapStandardClaims(context.Background(), "corp", map[string]any{"email": "x@example.com"})
	qt.Check(t, qt.ErrorMatches(err, ".*no subject.*"))
}

func TestMemoryIdentityStore(t *testing.T) {
	s := NewMemoryIdentityStore()
	ctx := context.Background()

	_, err := s.Lookup(ctx, "corp", "s1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrLinkNotFound)))

	l := &IdentityLink{UserID: "u1", Provider: "corp", Subject: "s1", Email: "a@example.com"}
	qt.Assert(t, qt.IsNil(s.Link(ctx, l)))
	qt.Check(t, qt.IsTrue(l.ID != ""))
	qt.Check(t, qt.IsFalse(l.LinkedAt.IsZero()))

	got, err := s.Lookup(ctx, "corp", "s1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.UserID, "u1"))

	// Same-user re-link touches LastUsedAt.
	relink := &IdentityLink{UserID: "u1", Provider: "corp", Subject: "s1"}
	qt.Assert(t, qt.IsNil(s.Link(ctx, relink)))
	qt.Check(t, qt.Equals(relink.ID, l.ID))
	qt.Check(t, qt.IsNotNil(relink.LastUsedAt))

	// A different user conflicts.
	err = s.Link(ctx, &IdentityLink{UserID: "u2", Provider: "corp", Subject: "s1"})
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrIdentityLinked)))

	qt.Assert(t, qt.IsNil(s.Link(ctx, &IdentityLink{UserID: "u1", Provider: "other", Subject: "x", LinkedAt: time.Now().Add(time.Second)})))

	links, _, err := s.List(ctx, "u1", "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(links, 2))

	links, _, err = s.List(ctx, "u1", "corp", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.HasLen(links, 1))

	qt.Check(t, qt.IsTrue(errors.Is(s.Unlink(ctx, "u2", l.ID), ErrLinkNotFound)))
	qt.Assert(t, qt.IsNil(s.Unlink(ctx, "u1", l.ID)))

	_, err = s.Lookup(ctx, "corp", "s1")
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrLinkNotFound)))
}

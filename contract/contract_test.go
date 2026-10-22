package contract

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestUserInfoToUser(t *testing.T) {
	u := UserInfo{ID: "u1", Name: "Alice", Contacts: map[string][]Contact{
		ChannelEmail: {{Address: "old@example.com"}, {Address: "alice@example.com", Verified: true}},
		ChannelPhone: {{Address: "+37120000000"}},
	}, Scope: "openid profile"}.ToUser()

	qt.Check(t, qt.IsTrue(u.Authorized()))
	qt.Check(t, qt.Equals(u.ID(), "u1"))
	qt.Check(t, qt.Equals(u.ClaimValue("name"), "Alice"))
	qt.Check(t, qt.Equals(u.ClaimValue("email"), "alice@example.com"))
	// An unverified address is never exposed.
	qt.Check(t, qt.Equals(u.ClaimValue("phone_number"), ""))
	qt.Check(t, qt.IsTrue(u.HasScope("openid")))
	qt.Check(t, qt.IsTrue(u.HasScope("profile")))
}

func TestUserInfoToUserOmitsEmptyClaims(t *testing.T) {
	u := UserInfo{ID: "u2"}.ToUser()

	qt.Check(t, qt.Equals(u.ClaimValue("name"), ""))
	qt.Check(t, qt.Equals(u.ClaimValue("email"), ""))
}

func TestPreferredContact(t *testing.T) {
	info := UserInfo{Contacts: map[string][]Contact{
		"email": {{Address: "a"}, {Address: "b", Verified: true}, {Address: "c", Primary: true}},
	}}

	got, ok := info.PreferredContact("email")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(got.Address, "b"))

	info.Contacts["email"][2].Verified = true

	got, _ = info.PreferredContact("email")
	qt.Check(t, qt.Equals(got.Address, "c"))

	info.Contacts["email"] = info.Contacts["email"][:1]

	got, _ = info.PreferredContact("email")
	qt.Check(t, qt.Equals(got.Address, "a"))

	_, ok = info.PreferredContact("phone")
	qt.Check(t, qt.IsFalse(ok))
}

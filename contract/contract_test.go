package contract

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestUserInfoToUser(t *testing.T) {
	u := UserInfo{ID: "u1", Name: "Alice", Email: "alice@example.com", Scope: "openid profile"}.ToUser()

	qt.Check(t, qt.IsTrue(u.Authorized()))
	qt.Check(t, qt.Equals(u.ID(), "u1"))
	qt.Check(t, qt.Equals(u.ClaimValue("name"), "Alice"))
	qt.Check(t, qt.Equals(u.ClaimValue("email"), "alice@example.com"))
	qt.Check(t, qt.IsTrue(u.HasScope("openid")))
	qt.Check(t, qt.IsTrue(u.HasScope("profile")))
}

func TestUserInfoToUserOmitsEmptyClaims(t *testing.T) {
	u := UserInfo{ID: "u2"}.ToUser()

	qt.Check(t, qt.Equals(u.ClaimValue("name"), ""))
	qt.Check(t, qt.Equals(u.ClaimValue("email"), ""))
}

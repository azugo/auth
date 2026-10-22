package session

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestAuthenticatedFactsFallBackForOlderSessions(t *testing.T) {
	// A session stored before the latest authentication was recorded answers from the session.
	old := &Session{ACR: "loa2", AMR: []string{"pwd", "otp"}, MFAMethod: "totp"}
	qt.Check(t, qt.Equals(old.AuthenticatedACR(), "loa2"))
	qt.Check(t, qt.DeepEquals(old.AuthenticatedMethods(), []string{"pwd", "otp"}))
	qt.Check(t, qt.IsTrue(old.AuthenticatedMFA()))

	// Once recorded, the latest authentication answers on its own.
	recent := &Session{ACR: "loa2", AMR: []string{"pwd", "otp"}, MFAMethod: "totp", AuthTime: time.Now(), AuthACR: "loa1", AuthMethods: []string{"pwd"}}
	qt.Check(t, qt.Equals(recent.AuthenticatedACR(), "loa1"))
	qt.Check(t, qt.DeepEquals(recent.AuthenticatedMethods(), []string{"pwd"}))
	qt.Check(t, qt.IsFalse(recent.AuthenticatedMFA()))

	// A recorded authentication without amr still answers on its own.
	noAMR := &Session{ACR: "loa2", AMR: []string{"otp"}, MFAMethod: "totp", AuthTime: time.Now(), AuthACR: "loa1"}
	qt.Check(t, qt.Equals(noAMR.AuthenticatedACR(), "loa1"))
	qt.Check(t, qt.HasLen(noAMR.AuthenticatedMethods(), 0))
	qt.Check(t, qt.IsFalse(noAMR.AuthenticatedMFA()))
}

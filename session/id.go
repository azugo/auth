package session

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

func newEntropy() ulid.MonotonicReader {
	return &ulid.LockedMonotonicReader{
		MonotonicReader: ulid.Monotonic(rand.Reader, 0),
	}
}

func newID(entropy ulid.MonotonicReader) (string, error) {
	id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), entropy)
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

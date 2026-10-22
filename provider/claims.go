package provider

import (
	"context"
	"errors"
	"strings"

	"azugo.io/auth/contract"
)

type (
	// UserInfo is the mapped identity returned by a ClaimMapper.
	UserInfo = contract.UserInfo
	// ClaimMapper converts validated raw provider claims into a UserInfo.
	ClaimMapper = contract.ClaimMapper
	// ClaimMapperFunc adapts a plain function to the ClaimMapper interface.
	ClaimMapperFunc = contract.ClaimMapperFunc
)

// protocolClaims are the id_token plumbing claims dropped from UserInfo.Claims.
var protocolClaims = map[string]struct{}{
	"iss": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {},
	"nonce": {}, "azp": {}, "at_hash": {}, "c_hash": {},
}

// claimTrue reports whether a boolean claim is true, sent as a JSON boolean or, as some IdPs do,
// the string "true".
func claimTrue(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	default:
		return false
	}
}

// MapStandardClaims is the shared default claim mapping: sub → ID, name (or
// given_name+family_name) → Name, email / phone_number with their _verified flags → Contacts,
// the _verified flags as booleans and everything else except protocol claims → Claims.
func MapStandardClaims(_ context.Context, _ string, raw map[string]any) (UserInfo, error) {
	info := UserInfo{Claims: make(map[string]any, len(raw))}

	for k, v := range raw {
		switch k {
		case "sub":
			info.ID, _ = v.(string)
		case "name":
			info.Name, _ = v.(string)
		case "email", "phone_number":
		case "email_verified", "phone_number_verified":
			info.Claims[k] = claimTrue(v)
		default:
			if _, skip := protocolClaims[k]; !skip {
				info.Claims[k] = v
			}
		}
	}

	if info.ID == "" {
		return info, errors.New("id_token claims contain no subject")
	}

	email, _ := raw["email"].(string)
	phone, _ := raw["phone_number"].(string)

	if email != "" || phone != "" {
		info.Contacts = make(map[string][]contract.Contact, 2)
	}

	if email != "" {
		info.Contacts[contract.ChannelEmail] = []contract.Contact{{Address: email, Verified: claimTrue(raw["email_verified"]), Primary: true}}
	}

	if phone != "" {
		info.Contacts[contract.ChannelPhone] = []contract.Contact{{Address: phone, Verified: claimTrue(raw["phone_number_verified"]), Primary: true}}
	}

	if info.Name == "" {
		given, _ := raw["given_name"].(string)
		family, _ := raw["family_name"].(string)
		info.Name = strings.TrimSpace(given + " " + family)
	}

	return info, nil
}

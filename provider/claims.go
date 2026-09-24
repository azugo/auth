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

// MapStandardClaims is the shared default claim mapping: sub → ID, name (or
// given_name+family_name) → Name, email → Email, everything else except protocol claims → Claims.
func MapStandardClaims(_ context.Context, _ string, raw map[string]any) (UserInfo, error) {
	info := UserInfo{Claims: make(map[string]any, len(raw))}

	for k, v := range raw {
		switch k {
		case "sub":
			info.ID, _ = v.(string)
		case "name":
			info.Name, _ = v.(string)
		case "email":
			info.Email, _ = v.(string)
		default:
			if _, skip := protocolClaims[k]; !skip {
				info.Claims[k] = v
			}
		}
	}

	if info.ID == "" {
		return info, errors.New("id_token claims contain no subject")
	}

	if info.Name == "" {
		given, _ := raw["given_name"].(string)
		family, _ := raw["family_name"].(string)
		info.Name = strings.TrimSpace(given + " " + family)
	}

	return info, nil
}

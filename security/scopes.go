package security

import "strings"

func HasScope(scopes []string, requiredScope string) bool {
	requiredScope = strings.TrimSpace(requiredScope)
	if requiredScope == "" {
		return true
	}

	for _, scope := range scopes {
		if strings.TrimSpace(scope) == requiredScope {
			return true
		}
	}

	return false
}

func HasRequiredScopes(granted []string, required []string) bool {
	if len(required) == 0 {
		return true
	}

	grantedSet := make(map[string]struct{}, len(granted))
	for _, item := range granted {
		grantedSet[strings.TrimSpace(item)] = struct{}{}
	}

	for _, item := range required {
		if _, ok := grantedSet[strings.TrimSpace(item)]; !ok {
			return false
		}
	}

	return true
}

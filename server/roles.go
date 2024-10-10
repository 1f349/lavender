package server

func HasRole(roles []string, test string) bool {
	for _, role := range roles {
		if role == test {
			return true
		}
	}
	return false
}

func ForEachRole(roles []string, next func(role string)) {
	for _, role := range roles {
		next(role)
	}
}

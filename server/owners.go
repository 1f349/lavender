package server

// DomainOwnership is the structure for storing if a user owns a domain
type DomainOwnership map[string][]string

func (d DomainOwnership) AllOwns(user string) []string {
	return d[user]
}

func (d DomainOwnership) Owns(user, domain string) bool {
	for _, i := range d[user] {
		if i == domain {
			return true
		}
	}
	return false
}

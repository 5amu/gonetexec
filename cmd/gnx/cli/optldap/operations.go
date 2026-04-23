package optldap

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

func Search(c *ldap.Conn, domain string, filter string, attributes ...string) (*ldap.SearchResult, error) {
	basedn := toDN(domain)
	return c.SearchWithPaging(ldap.NewSearchRequest(
		basedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	),
		1000,
	)
}

func FindObjects(c *ldap.Conn, domain string, filter string, attributes ...string) ([]map[string]interface{}, error) {
	res, err := Search(c, domain, filter, attributes...)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no user found in search")
	}

	var out []map[string]interface{}
	for _, r := range res.Entries {
		app := make(map[string]interface{})
		for _, a := range attributes {
			tmp := r.GetAttributeValues(a)
			switch len(tmp) {
			case 0:
				app[a] = nil
			case 1:
				app[a] = tmp[0]
			default:
				app[a] = tmp
			}
		}
		out = append(out, app)
	}
	return out, nil
}

func FindObjectsWithCallback(c *ldap.Conn, domain string, filter string, callback func(map[string]interface{}) error, attributes ...string) error {
	all, err := FindObjects(c, domain, filter, attributes...)
	if err != nil {
		return err
	}
	for _, obj := range all {
		if err = callback(obj); err != nil {
			return err
		}
	}
	return nil
}

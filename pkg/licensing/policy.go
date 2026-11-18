package licensing

import (
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

// Policy selects components by license. A component is excluded when any of its licenses
// matches one of the configured categories or license expressions.
type Policy struct {
	categories map[types.LicenseCategory]struct{}
	licenses   map[string]struct{}
	scanner    Scanner
}

// NewPolicy builds a license policy. Entries can be license categories such as
// "forbidden" or license expressions such as "GPL-3.0-only" and "MIT OR Apache-2.0".
// The optional prefix "category:" or "license:" disambiguates an entry.
func NewPolicy(entries []string, categories map[types.LicenseCategory][]string) Policy {
	if len(categories) == 0 {
		categories = map[types.LicenseCategory][]string{
			types.CategoryForbidden:    expression.ForbiddenLicenses,
			types.CategoryRestricted:   expression.RestrictedLicenses,
			types.CategoryReciprocal:   expression.ReciprocalLicenses,
			types.CategoryNotice:       expression.NoticeLicenses,
			types.CategoryPermissive:   expression.PermissiveLicenses,
			types.CategoryUnencumbered: expression.UnencumberedLicenses,
		}
	}
	policy := Policy{
		categories: make(map[types.LicenseCategory]struct{}),
		licenses:   make(map[string]struct{}),
		scanner:    NewScanner(categories),
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		kind, value, found := strings.Cut(entry, ":")
		if !found {
			value = entry
		} else {
			kind = strings.TrimSpace(kind)
			value = strings.TrimSpace(value)
		}

		if (found && strings.EqualFold(kind, "category")) || (!found && isLicenseCategory(value)) {
			policy.categories[licenseCategory(value)] = struct{}{}
			continue
		}
		if found && !strings.EqualFold(kind, "license") {
			// Unknown prefixes are treated as part of the license name.
			value = entry
		}

		policy.addLicense(value)
	}

	return policy
}

// Empty reports whether the policy contains no criteria.
func (p Policy) Empty() bool {
	return len(p.categories) == 0 && len(p.licenses) == 0
}

// Excludes reports whether any of the licenses violates the policy.
func (p Policy) Excludes(licenses []string) bool {
	licenses = lo.Compact(lo.Map(licenses, func(license string, _ int) string {
		return strings.TrimSpace(license)
	}))

	if len(licenses) == 0 {
		_, excluded := p.categories[types.CategoryUnknown]
		return excluded
	}

	for _, license := range licenses {
		if p.matchesLicense(license) {
			return true
		}
		category, _ := p.scanner.Scan(license)
		if _, excluded := p.categories[category]; excluded {
			return true
		}
	}
	return false
}

func (p *Policy) addLicense(license string) {
	if names := normalizeLicenseNames(license); len(names) > 0 {
		for _, name := range names {
			p.licenses[name] = struct{}{}
		}
		return
	}
	p.licenses[strings.ToLower(strings.TrimSpace(license))] = struct{}{}
}

func (p Policy) matchesLicense(license string) bool {
	names := normalizeLicenseNames(license)
	if len(names) == 0 {
		names = []string{strings.ToLower(strings.TrimSpace(license))}
	}
	for _, name := range names {
		if _, excluded := p.licenses[name]; excluded {
			return true
		}
	}
	return false
}

func normalizeLicenseNames(license string) []string {
	expr, err := expression.Normalize(license, NormalizeLicenseExpression, expression.NormalizeForSPDX)
	if err != nil {
		return nil
	}

	var names []string
	var walk func(expression.Expression)
	walk = func(expr expression.Expression) {
		switch e := expr.(type) {
		case expression.SimpleExpr:
			names = append(names, strings.ToLower(e.String()))
		case expression.CompoundExpr:
			walk(e.Left())
			walk(e.Right())
		}
	}
	walk(expr)
	return lo.Uniq(names)
}

func isLicenseCategory(value string) bool {
	switch strings.ToLower(value) {
	case string(types.CategoryForbidden),
		string(types.CategoryRestricted),
		string(types.CategoryReciprocal),
		string(types.CategoryNotice),
		string(types.CategoryPermissive),
		string(types.CategoryUnencumbered),
		string(types.CategoryUnknown):
		return true
	default:
		return false
	}
}

func licenseCategory(value string) types.LicenseCategory {
	return types.LicenseCategory(strings.ToLower(strings.TrimSpace(value)))
}

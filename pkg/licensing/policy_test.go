package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestPolicy_Excludes(t *testing.T) {
	tests := []struct {
		name     string
		entries  []string
		licenses []string
		want     bool
	}{
		{
			name:     "empty policy",
			licenses: []string{"GPL-3.0-only"},
			want:     false,
		},
		{
			name:     "category",
			entries:  []string{"forbidden"},
			licenses: []string{"AGPL-3.0-only"},
			want:     true,
		},
		{
			name:     "category prefix",
			entries:  []string{"category:restricted"},
			licenses: []string{"GPL-3.0-only"},
			want:     true,
		},
		{
			name:     "exact license",
			entries:  []string{"GPL-3.0"},
			licenses: []string{"GPL-3.0-only"},
			want:     true,
		},
		{
			name:     "different version is not an exact match",
			entries:  []string{"GPL-3.0"},
			licenses: []string{"GPL-2.0-only"},
			want:     false,
		},
		{
			name:     "compound expression",
			entries:  []string{"license:MIT AND GPL-3.0-only"},
			licenses: []string{"GPL-3.0-only"},
			want:     true,
		},
		{
			name:     "unknown category matches a missing license",
			entries:  []string{"unknown"},
			licenses: nil,
			want:     true,
		},
		{
			name:     "unknown category matches an unrecognized license",
			entries:  []string{"unknown"},
			licenses: []string{"proprietary"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := licensing.NewPolicy(tt.entries, map[types.LicenseCategory][]string{
				types.CategoryForbidden:  {"AGPL-3.0-only"},
				types.CategoryRestricted: {"GPL-3.0-only"},
			})
			assert.Equal(t, tt.want, policy.Excludes(tt.licenses))
		})
	}
}

func TestPolicy_DefaultCategories(t *testing.T) {
	policy := licensing.NewPolicy([]string{"forbidden"}, nil)
	assert.True(t, policy.Excludes([]string{"AGPL-3.0-only"}))
}

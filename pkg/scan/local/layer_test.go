package local

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFillVulnerabilityLayers(t *testing.T) {
	osLayer := ftypes.Layer{DiffID: "sha256:os-layer"}
	langLayer := ftypes.Layer{DiffID: "sha256:lang-layer"}
	existingLayer := ftypes.Layer{DiffID: "sha256:existing-layer"}

	target := types.ScanTarget{
		Packages: ftypes.Packages{
			{
				ID:      "openssl@1.1.1",
				Name:    "openssl",
				Version: "1.1.1",
				Layer:   osLayer,
			},
		},
		Applications: ftypes.Applications{
			{
				Type:     ftypes.Composer,
				FilePath: "app/composer.lock",
				Packages: ftypes.Packages{
					{
						ID:      "guzzlehttp/guzzle@6.2.0",
						Name:    "guzzlehttp/guzzle",
						Version: "6.2.0",
						Layer:   langLayer,
					},
				},
			},
		},
	}

	results := types.Results{
		{
			Class: types.ClassOSPkg,
			Vulnerabilities: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-OS",
					PkgID:           "openssl@1.1.1",
				},
				{
					VulnerabilityID:  "CVE-OS-WITHOUT-ID",
					PkgName:          "openssl",
					InstalledVersion: "1.1.1",
				},
			},
		},
		{
			Class: types.ClassLangPkg,
			Vulnerabilities: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-LANG",
					PkgID:           "guzzlehttp/guzzle@6.2.0",
					PkgPath:         "app/composer.lock",
				},
				{
					VulnerabilityID: "CVE-EXISTING",
					PkgID:           "guzzlehttp/guzzle@6.2.0",
					Layer:           existingLayer,
				},
			},
		},
	}

	fillVulnerabilityLayers(results, target)

	assert.Equal(t, osLayer, results[0].Vulnerabilities[0].Layer)
	assert.Equal(t, osLayer, results[0].Vulnerabilities[1].Layer)
	assert.Equal(t, langLayer, results[1].Vulnerabilities[0].Layer)
	assert.Equal(t, existingLayer, results[1].Vulnerabilities[1].Layer)
}

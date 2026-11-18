package cyclonedx

import (
	"context"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Writer implements types.Writer
type Writer struct {
	output        io.Writer
	format        cdx.BOMFileFormat
	specVersion   cdx.SpecVersion
	licensePolicy licensing.Policy
	marshaler     cyclonedx.Marshaler
}

type Option func(*Writer)

// WithSpecVersion sets the CycloneDX specification version. Supported values are "1.6" and "1.7".
func WithSpecVersion(version string) Option {
	return func(w *Writer) {
		switch version {
		case "1.6":
			w.specVersion = cdx.SpecVersion1_6
		case "1.7":
			w.specVersion = cdx.SpecVersion1_7
		}
	}
}

// WithLicensePolicy excludes components matching the license policy.
func WithLicensePolicy(entries []string, categories map[ftypes.LicenseCategory][]string) Option {
	return func(w *Writer) {
		w.licensePolicy = licensing.NewPolicy(entries, categories)
	}
}

func NewWriter(output io.Writer, appVersion string, opts ...Option) Writer {
	w := Writer{
		output:      output,
		format:      cdx.BOMFileFormatJSON,
		specVersion: cdx.SpecVersion1_6,
	}
	for _, opt := range opts {
		opt(&w)
	}

	marshalerOpts := []cyclonedx.MarshalerOption{
		cyclonedx.WithSpecVersion(w.specVersion),
	}
	if !w.licensePolicy.Empty() {
		marshalerOpts = append(marshalerOpts, cyclonedx.WithLicensePolicy(w.licensePolicy))
	}
	w.marshaler = cyclonedx.NewMarshaler(appVersion, marshalerOpts...)
	return w
}

// Write writes the results in CycloneDX format
func (w Writer) Write(ctx context.Context, report types.Report) error {
	bom, err := w.marshaler.MarshalReport(ctx, report)
	if err != nil {
		return xerrors.Errorf("CycloneDX marshal error: %w", err)
	}

	encoder := cdx.NewBOMEncoder(w.output, w.format)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}

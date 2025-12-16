// Copyright 2025 Lean Security Co.
// SPDX-License-Identifier: Apache-2.0

// Package reporter provides output formatting for audit results.
package reporter

import "github.com/leansecurity-co/gwork/internal/audit"

// Reporter defines the interface for audit result output.
type Reporter interface {
	// WriteFilesByOwner writes files-by-owner report.
	WriteFilesByOwner(records []audit.FileRecord) error

	// WriteExternalSharing writes external sharing report.
	WriteExternalSharing(records []audit.ExternalShareRecord) error
}

// Copyright 2025 Lean Security Co.
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/leansecurity-co/gwork/internal/audit"
)

// CSVReporter generates CSV reports.
type CSVReporter struct {
	outputDir string
}

// NewCSVReporter creates a new CSV reporter.
func NewCSVReporter(outputDir string) (*CSVReporter, error) {
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}
	return &CSVReporter{outputDir: outputDir}, nil
}

// WriteFilesByOwner generates the files-by-owner CSV.
func (r *CSVReporter) WriteFilesByOwner(records []audit.FileRecord) (err error) {
	// Sort by owner email
	sort.Slice(records, func(i, j int) bool {
		if records[i].OwnerEmail != records[j].OwnerEmail {
			return records[i].OwnerEmail < records[j].OwnerEmail
		}
		return records[i].FileName < records[j].FileName
	})

	path := filepath.Join(r.outputDir, "files_by_owner.csv")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", cerr)
		}
	}()

	writer := csv.NewWriter(file)

	// Write header
	header := []string{
		"owner_email", "file_id", "file_name", "file_type",
		"created_time", "modified_time", "size_bytes",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write records
	for _, rec := range records {
		createdTime := ""
		if !rec.CreatedTime.IsZero() {
			createdTime = rec.CreatedTime.Format("2006-01-02T15:04:05Z")
		}
		modifiedTime := ""
		if !rec.ModifiedTime.IsZero() {
			modifiedTime = rec.ModifiedTime.Format("2006-01-02T15:04:05Z")
		}

		row := []string{
			rec.OwnerEmail,
			rec.FileID,
			rec.FileName,
			rec.FileType,
			createdTime,
			modifiedTime,
			strconv.FormatInt(rec.SizeBytes, 10),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// WriteExternalSharing generates the external-sharing CSV.
func (r *CSVReporter) WriteExternalSharing(records []audit.ExternalShareRecord) (err error) {
	// Sort by owner email
	sort.Slice(records, func(i, j int) bool {
		if records[i].OwnerEmail != records[j].OwnerEmail {
			return records[i].OwnerEmail < records[j].OwnerEmail
		}
		return records[i].FileName < records[j].FileName
	})

	path := filepath.Join(r.outputDir, "external_sharing.csv")
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", cerr)
		}
	}()

	writer := csv.NewWriter(file)

	// Write header
	header := []string{
		"owner_email", "file_id", "file_name", "shared_with_email",
		"shared_with_domain", "permission_type", "permission_role", "shared_date",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write records
	for _, rec := range records {
		sharedDate := ""
		if !rec.SharedDate.IsZero() {
			sharedDate = rec.SharedDate.Format("2006-01-02T15:04:05Z")
		}
		row := []string{
			rec.OwnerEmail,
			rec.FileID,
			rec.FileName,
			rec.SharedWithEmail,
			rec.SharedWithDomain,
			rec.PermissionType,
			rec.PermissionRole,
			sharedDate,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// OutputDir returns the output directory path.
func (r *CSVReporter) OutputDir() string {
	return r.outputDir
}

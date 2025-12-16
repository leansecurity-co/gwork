// Copyright 2025 Lean Security Co.
// SPDX-License-Identifier: Apache-2.0

// Package main provides the gwork CLI tool for Google Workspace security audits.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/leansecurity-co/gwork/internal/audit"
	"github.com/leansecurity-co/gwork/internal/config"
	"github.com/leansecurity-co/gwork/internal/reporter"
	"github.com/leansecurity-co/gwork/pkg/exitcode"
	"github.com/spf13/cobra"
)

var (
	version = "0.1.0"

	cfgFile string
	verbose bool
	quiet   bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(exitcode.InternalError)
	}
}

var rootCmd = &cobra.Command{
	Use:   "gwork",
	Short: "Google Workspace security and audit tool",
	Long: `gwork is a CLI tool for auditing Google Workspace Drive files.
It helps identify files shared externally and generates reports
grouped by file owner.`,
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run audit operations",
	Long:  `Run various audit operations on Google Workspace Drive.`,
}

var auditFilesCmd = &cobra.Command{
	Use:   "files",
	Short: "Generate files by owner CSV",
	Long:  `Fetch all files from Google Drive across the domain and generate a CSV grouped by owner.`,
	RunE:  runAuditFiles,
}

var auditSharingCmd = &cobra.Command{
	Use:   "sharing",
	Short: "Generate external sharing CSV",
	Long:  `Generate a list of files shared externally (outside the organization domain).`,
	RunE:  runAuditSharing,
}

var auditAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Run all audits",
	Long:  `Run all audit operations: files by owner and external sharing.`,
	RunE:  runAuditAll,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  `Commands for managing gwork configuration.`,
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config file",
	Long:  `Create a new .gwork.yaml configuration file with default values.`,
	RunE:  runConfigInit,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("gwork v%s\n", version)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is .gwork.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-error output")

	// Build command tree
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)

	auditCmd.AddCommand(auditFilesCmd)
	auditCmd.AddCommand(auditSharingCmd)
	auditCmd.AddCommand(auditAllCmd)

	configCmd.AddCommand(configInitCmd)
}

func loadConfig() (*config.Config, error) {
	return config.Load(cfgFile)
}

func runAuditFiles(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ctx := context.Background()
	auditor, err := audit.NewAuditor(cfg)
	if err != nil {
		return fmt.Errorf("failed to create auditor: %w", err)
	}

	if !quiet {
		fmt.Println("Fetching files from Google Drive...")
	}

	result, err := auditor.AuditFiles(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	rep, err := reporter.NewCSVReporter(cfg.Output.Directory)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	if err := rep.WriteFilesByOwner(result.FileRecords); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	if !quiet {
		fmt.Printf("Files audit complete. Total files: %d\n", result.TotalFiles)
		fmt.Printf("Report saved to: %s/files_by_owner.csv\n", rep.OutputDir())
	}

	return nil
}

func runAuditSharing(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ctx := context.Background()
	auditor, err := audit.NewAuditor(cfg)
	if err != nil {
		return fmt.Errorf("failed to create auditor: %w", err)
	}

	if !quiet {
		fmt.Println("Analyzing external sharing...")
	}

	result, err := auditor.AuditExternalSharing(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	rep, err := reporter.NewCSVReporter(cfg.Output.Directory)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	if err := rep.WriteExternalSharing(result.ExternalShares); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	if !quiet {
		fmt.Printf("Sharing audit complete. Files processed: %d\n", result.FilesProcessed)
		fmt.Printf("External shares found: %d\n", result.TotalExternalShares)
		fmt.Printf("Report saved to: %s/external_sharing.csv\n", rep.OutputDir())

		if len(result.Errors) > 0 {
			fmt.Printf("Warnings: %d files could not be processed\n", len(result.Errors))
			if verbose {
				for _, e := range result.Errors {
					fmt.Printf("  - %v\n", e)
				}
			}
		}
	}

	return nil
}

func runAuditAll(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	ctx := context.Background()
	auditor, err := audit.NewAuditor(cfg)
	if err != nil {
		return fmt.Errorf("failed to create auditor: %w", err)
	}

	if !quiet {
		fmt.Println("Running all audits...")
	}

	filesResult, sharingResult, err := auditor.AuditAll(ctx)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	rep, err := reporter.NewCSVReporter(cfg.Output.Directory)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	if err := rep.WriteFilesByOwner(filesResult.FileRecords); err != nil {
		return fmt.Errorf("failed to write files report: %w", err)
	}

	if err := rep.WriteExternalSharing(sharingResult.ExternalShares); err != nil {
		return fmt.Errorf("failed to write sharing report: %w", err)
	}

	if !quiet {
		fmt.Printf("Files audit complete. Total files: %d\n", filesResult.TotalFiles)
		fmt.Printf("Report saved to: %s/files_by_owner.csv\n", rep.OutputDir())
		fmt.Printf("Sharing audit complete. Files processed: %d\n", sharingResult.FilesProcessed)
		fmt.Printf("External shares found: %d\n", sharingResult.TotalExternalShares)
		fmt.Printf("Report saved to: %s/external_sharing.csv\n", rep.OutputDir())

		if len(sharingResult.Errors) > 0 {
			fmt.Printf("Warnings: %d files could not be processed\n", len(sharingResult.Errors))
			if verbose {
				for _, e := range sharingResult.Errors {
					fmt.Printf("  - %v\n", e)
				}
			}
		}
	}

	return nil
}

func runConfigInit(cmd *cobra.Command, args []string) error {
	configPath := ".gwork.yaml"

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file %s already exists", configPath)
	}

	cfg := config.NewDefault()
	if err := cfg.Save(configPath); err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}

	fmt.Printf("Created %s\n", configPath)
	fmt.Println("Please edit the file to add your Google service account credentials.")
	return nil
}

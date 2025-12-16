# gwork

A Golang CLI tool for Google Workspace security and audit operations.

## Features

- Audit all Google Drive files across a Google Workspace domain
- Generate files-by-owner CSV reports with comprehensive file metadata
- Identify files shared externally (outside the organization domain)
- Service account authentication with domain-wide delegation
- Support for shared drives (Team Drives)
- Configurable via YAML configuration file
- JSON and CSV output formats
- Verbose and quiet modes for flexible logging

## Installation

Requires Go 1.23 or later.

```bash
go install github.com/leansecurity-co/gwork@latest
```

To uninstall:

```bash
rm $(go env GOPATH)/bin/gwork
```

Or build from source:

```bash
git clone https://github.com/leansecurity-co/gwork.git
cd gwork
make build
```

## Usage

```bash
gwork <command> [options]

Commands:
  audit files    List all files grouped by owner
  audit sharing  List files shared externally
  audit all      Run all audit operations
  config init    Create .gwork.yaml configuration file
  version        Print the version number

Options:
  -c, --config   Path to config file (default: .gwork.yaml)
  -v, --verbose  Enable verbose output
  -q, --quiet    Suppress non-error output

Examples:
  gwork audit files
  gwork audit sharing
  gwork audit all
  gwork config init
  gwork audit files --config /path/to/.gwork.yaml
  gwork audit sharing --verbose
```

## Quick Start

Initialize configuration in your project:

```bash
gwork config init
```

Edit `.gwork.yaml` to add your Google service account credentials:

```yaml
google:
  service_account_file: "path/to/service-account.json"
  admin_email: "admin@company.com"
  domain: "company.com"
```

Run the files audit:

```bash
gwork audit files
```

Run the external sharing audit:

```bash
gwork audit sharing
```

Or run all audits at once:

```bash
gwork audit all
```

## Configuration

The `.gwork.yaml` file controls authentication, audit behavior, and output settings:

```yaml
# Google Workspace configuration
google:
  # Path to the service account JSON key file
  # The service account must have domain-wide delegation enabled
  # Required scopes:
  #   - https://www.googleapis.com/auth/drive.readonly
  #   - https://www.googleapis.com/auth/drive.metadata.readonly
  service_account_file: "path/to/service-account.json"

  # Admin email for domain-wide delegation impersonation
  # This user must have admin privileges in the Google Workspace domain
  admin_email: "admin@company.com"

  # Organization domain (used to identify external shares)
  # Files shared with users outside this domain are considered external
  domain: "company.com"

# Audit configuration
audit:
  # Include files from shared drives in the audit
  include_shared_drives: true

  # Number of items to fetch per API page (max 1000)
  # Higher values may improve performance but use more memory
  page_size: 1000

# Output configuration
output:
  # Output format: csv or json
  format: csv

  # Directory to save output files
  # Created automatically if it doesn't exist
  directory: "./output"
```

### Configuration Options

- **google.service_account_file**: Path to the Google Cloud service account JSON key file with domain-wide delegation enabled
- **google.admin_email**: Email address of a Google Workspace admin user to impersonate for domain-wide operations
- **google.domain**: Your organization's primary domain name for identifying external sharing
- **audit.include_shared_drives**: Boolean flag to include shared/team drives in audits
- **audit.page_size**: Number of items per API request (1-1000, higher values = fewer API calls)
- **output.format**: Output format for reports (csv or json)
- **output.directory**: Directory where reports will be saved

## How It Works

gwork performs domain-wide audits of Google Workspace Drive files using service account authentication with domain-wide delegation:

1. **Authentication**: Uses a Google Cloud service account with domain-wide delegation to impersonate an admin user and access Drive data across the entire organization

2. **File Discovery**: Iterates through all users in the domain and fetches their Drive files using the Google Drive API

3. **Metadata Collection**: For each file, collects metadata including owner, name, type, creation/modification dates, size, and sharing permissions

4. **External Sharing Analysis**: Examines file permissions to identify shares with users, groups, or domains outside the organization

5. **Report Generation**: Outputs results in CSV or JSON format with detailed information grouped by file owner

The tool respects Google API rate limits and handles pagination automatically.

## Example Output

### files_by_owner.csv

```text
owner_email,file_id,file_name,file_type,created_time,modified_time,size_bytes
user@company.com,1a2b3c4d5e6f,Q1 Budget.xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,2025-01-15T10:30:00Z,2025-01-20T14:45:00Z,524288
user@company.com,7g8h9i0j1k2l,Marketing Plan.docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document,2025-02-01T09:00:00Z,2025-02-10T16:30:00Z,2097152
admin@company.com,3m4n5o6p7q8r,Company Policies,application/vnd.google-apps.folder,2024-12-01T08:00:00Z,2025-01-05T11:00:00Z,0
```

### external_sharing.csv

```text
owner_email,file_id,file_name,shared_with_email,shared_with_domain,permission_type,permission_role,shared_date
user@company.com,1a2b3c4d5e6f,Q1 Budget.xlsx,external@partner.com,partner.com,user,reader,2025-01-20T15:30:00Z
marketing@company.com,9s0t1u2v3w4x,Product Roadmap.pptx,consultant@external.org,external.org,user,writer,2025-02-05T10:15:00Z
finance@company.com,5y6z7a8b9c0d,Financial Report.pdf,anyone@,*,anyone,reader,2025-01-10T12:00:00Z
```

### Console Output

```text
$ gwork audit all
Fetching files from Google Drive...
Files audit complete. Total files: 1,234
Report saved to: ./output/files_by_owner.csv
Analyzing external sharing...
Sharing audit complete. Files processed: 1,234
External shares found: 42
Report saved to: ./output/external_sharing.csv
```

## Exit Codes

| Code | Description                          |
| ---- | ------------------------------------ |
| 0    | Operation completed successfully     |
| 1    | Configuration error                  |
| 2    | Authentication error                 |
| 3    | Google API error                     |
| 10   | Internal error                       |

Use exit codes for automation and CI/CD integration:

```bash
# Run audit and handle errors
if ! gwork audit files; then
  echo "Audit failed with exit code $?"
  exit 1
fi
```

## Prerequisites

Before using gwork, you need to set up a Google Cloud service account with domain-wide delegation:

1. **Create a Google Cloud Project**
   - Go to the [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one

2. **Enable the Google Drive API**
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google Drive API" and enable it

3. **Create a Service Account**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "Service Account"
   - Fill in the service account details and create

4. **Enable Domain-Wide Delegation**
   - Click on the created service account
   - Go to "Show Domain-Wide Delegation"
   - Enable "Enable Google Workspace Domain-wide Delegation"
   - Note the service account's "Client ID"

5. **Download Service Account Key**
   - In the service account details, go to "Keys" tab
   - Click "Add Key" > "Create new key"
   - Select JSON format and download the key file

6. **Authorize in Google Workspace Admin Console**
   - Go to [Google Workspace Admin Console](https://admin.google.com/)
   - Navigate to "Security" > "API Controls" > "Domain-wide Delegation"
   - Click "Add new" and enter the service account's Client ID
   - Add these OAuth scopes:
     - `https://www.googleapis.com/auth/drive.readonly`
     - `https://www.googleapis.com/auth/drive.metadata.readonly`
   - Click "Authorize"

7. **Configure gwork**
   - Run `gwork config init` to create `.gwork.yaml`
   - Set `service_account_file` to the path of your downloaded JSON key
   - Set `admin_email` to a Google Workspace admin user's email
   - Set `domain` to your organization's domain

## Output File Schemas

### Files By Owner Schema

| Column        | Description                                           |
| ------------- | ----------------------------------------------------- |
| owner_email   | Email address of the file owner                       |
| file_id       | Unique Google Drive file ID                           |
| file_name     | Name of the file                                      |
| file_type     | MIME type (e.g., application/pdf, text/plain)        |
| created_time  | File creation timestamp (RFC3339 format)              |
| modified_time | Last modification timestamp (RFC3339 format)          |
| size_bytes    | File size in bytes (0 for Google Docs, Sheets, etc.) |

### External Sharing Schema

| Column             | Description                                                       |
| ------------------ | ----------------------------------------------------------------- |
| owner_email        | Email address of the file owner                                   |
| file_id            | Unique Google Drive file ID                                       |
| file_name          | Name of the file                                                  |
| shared_with_email  | Email of the external user or group (or "anyone" for public)      |
| shared_with_domain | Domain of the external recipient (or "*" for public access)       |
| permission_type    | Type: user, group, domain, or anyone                              |
| permission_role    | Role: reader, commenter, writer, owner                            |
| shared_date        | Timestamp when permission was granted (if available, RFC3339)     |

## Limitations

- Requires Google Workspace domain admin privileges for domain-wide delegation
- Service account must be explicitly authorized in Google Workspace Admin Console
- Does not audit files in user's Trash folders
- File size is 0 for native Google Workspace files (Docs, Sheets, Slides, Forms)
- Shared drive support depends on API access permissions
- Subject to Google Drive API rate limits and quotas
- Does not perform retroactive permission history analysis beyond current state

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Run all checks (test + lint)
make check

# Run CI checks (no auto-formatting)
make ci

# Build binary
make build

# Clean build artifacts
make clean

# Download and tidy dependencies
make deps

# Show all available targets
make help
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

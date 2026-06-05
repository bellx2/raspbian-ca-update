# raspbian-ca-update

A tool for updating CA certificates on old Raspbian systems

Version: 1.1.0

## Overview

On older Raspbian systems, CA certificates may not be updatable through the standard package management system due to OpenSSL version dependencies. This tool solves that problem by directly downloading and updating the latest CA certificates.

## Features

- Automatically downloads the latest CA certificates from curl.se
- Creates automatic backup of existing certificates
- Validates downloaded PEM bundle before installation
- Installs certificates atomically via a temporary file
- Automatically rolls back from backup on post-install failures
- Rebuilds certificate hash links
- SSL connection test functionality
- Checks current certificate status

## Installation

```bash
go build -o raspbian-ca-update raspbian_ca_update.go
sudo cp raspbian-ca-update /usr/local/bin/
```

## Usage

### Update CA certificates
```bash
sudo raspbian-ca-update
```

### Check current certificate status
```bash
raspbian-ca-update --check
```

### Show help
```bash
raspbian-ca-update --help
```

### Force update on non-Raspbian systems
```bash
sudo raspbian-ca-update --force
```

### Update with insecure mode (skip SSL verification)
```bash
sudo raspbian-ca-update --insecure
```

### Combine options
```bash
sudo raspbian-ca-update --force --insecure
```

## Options

- `--help`, `-h`: Show help message
- `--version`, `-v`: Show version information
- `--check`: Check current CA certificate status
- `--force`: Force execution even on non-Raspbian systems
- `--insecure`: Skip SSL certificate verification when downloading (use when current certificates are outdated)

## How it Works

1. Creates backup of existing CA certificates (`/etc/ssl/certs/ca-certificates.crt.backup`)
2. Downloads latest CA certificates from curl.se
3. Validates the downloaded bundle (PEM markers and size limits)
4. Writes to a temporary file (`/etc/ssl/certs/ca-certificates.crt.tmp`) and atomically replaces the live bundle
5. Sets file permissions (644)
6. Rebuilds certificate hash links
7. Runs SSL connection test

If a failure occurs after the bundle has been replaced (for example, during permission changes), the tool automatically restores the backup. If automatic rollback fails, restore manually:

```bash
sudo cp /etc/ssl/certs/ca-certificates.crt.backup /etc/ssl/certs/ca-certificates.crt
```

## Requirements

- Go 1.24.4 or later
- Root privileges (sudo)
- Internet connection

## License

MIT License

Copyright (c) 2025 Ryu Tanabe (bellx2)

## Author

Ryu Tanabe (bellx2)  
https://github.com/bellx2
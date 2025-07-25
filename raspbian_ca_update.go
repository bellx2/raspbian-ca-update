// Copyright (c) 2025 Ryu Tanabe (bellx2)
// https://github.com/bellx2
//
// This software is released under the MIT License.
// https://opensource.org/licenses/MIT

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	version    = "1.0.0"
	caURL      = "https://curl.se/ca/cacert.pem"
	caPath     = "/etc/ssl/certs/ca-certificates.crt"
	backupPath = "/etc/ssl/certs/ca-certificates.crt.backup"
	certsDir   = "/etc/ssl/certs"
)

func main() {
	fmt.Printf("Raspbian CA Update Tool v%s\n", version)
	fmt.Println("===========================")

	if os.Geteuid() != 0 {
		fmt.Println("Error: This tool requires root privileges")
		fmt.Println("Please run with sudo: sudo raspbian-ca-update")
		os.Exit(1)
	}

	forceMode := false
	insecureMode := false
	
	// Parse command line arguments
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--help", "-h":
			showHelp()
			return
		case "--version", "-v":
			fmt.Printf("raspbian-ca-update v%s\n", version)
			fmt.Println("Copyright (c) 2025 Ryu Tanabe (bellx2)")
			fmt.Println("https://github.com/bellx2")
			return
		case "--check":
			checkCertificates()
			return
		case "--force":
			forceMode = true
		case "--insecure":
			insecureMode = true
		}
	}

	// Check if system is Raspbian
	if !forceMode && !isRaspbian() {
		fmt.Println("Error: This system is not Raspbian")
		fmt.Println("This tool is designed specifically for Raspbian systems.")
		fmt.Println("Use --force to run anyway (not recommended)")
		os.Exit(1)
	}

	// Check CA certificate path
	if !forceMode && !isCAPathValid() {
		fmt.Println("Error: CA certificate path is not standard")
		fmt.Printf("Expected path: %s\n", caPath)
		fmt.Println("This system may use a different certificate location.")
		fmt.Println("Use --force to run anyway (not recommended)")
		os.Exit(1)
	}

	// Show warning if using insecure mode
	if insecureMode {
		fmt.Println("Warning: Running in insecure mode - SSL certificate verification disabled")
	}

	// Main update process
	if err := updateCACertificates(insecureMode); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CA certificates updated successfully!")
	fmt.Println("Testing SSL connection...")

	if err := testSSLConnection(); err != nil {
		fmt.Printf("Warning: SSL test failed: %v\n", err)
	} else {
		fmt.Println("SSL connection test passed!")
	}
}

func showHelp() {
	fmt.Println(`Usage: raspbian-ca-update [options]

Options:
  --help, -h     Show this help message
  --version, -v  Show version information
  --check        Check current CA certificates status
  --force        Force execution even on non-Raspbian systems
  --insecure     Skip SSL certificate verification when downloading

Description:
  Updates CA certificates on old Raspbian systems where package
  management cannot update ca-certificates due to OpenSSL version
  dependencies.

Examples:
  sudo raspbian-ca-update                # Update CA certificates
  raspbian-ca-update --check             # Check current status
  sudo raspbian-ca-update --force        # Force update on any system
  sudo raspbian-ca-update --insecure     # Download without SSL verification
  sudo raspbian-ca-update --force --insecure # Combine options
`)
}

func checkCertificates() {
	fmt.Println("Checking current CA certificates...")

	// Check if file exists
	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Println("CA certificates file not found:", caPath)
		return
	}

	// Display file information
	info, err := os.Stat(caPath)
	if err != nil {
		fmt.Printf("Error checking file: %v\n", err)
		return
	}

	fmt.Printf("File: %s\n", caPath)
	fmt.Printf("Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	fmt.Printf("Size: %d bytes\n", info.Size())

	// Count certificates
	data, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	certs, err := parsePEMCertificates(data)
	if err != nil {
		fmt.Printf("Error parsing certificates: %v\n", err)
		return
	}

	fmt.Printf("Certificates count: %d\n", len(certs))

	// SSL connection test
	fmt.Println("\nTesting SSL connection...")
	if err := testSSLConnection(); err != nil {
		fmt.Printf("SSL test failed: %v\n", err)
	} else {
		fmt.Println("SSL connection test passed!")
	}
}

func updateCACertificates(insecure bool) error {
	fmt.Println("Starting CA certificates update...")

	// 1. Create backup
	if err := createBackup(); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// 2. Download new CA certificates
	if err := downloadCACertificates(insecure); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// 3. Set permissions
	if err := os.Chmod(caPath, 0644); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	// 4. Rebuild hash links
	if err := rehashCertificates(); err != nil {
		fmt.Printf("Warning: rehash failed: %v\n", err)
		fmt.Println("You may need to run manually: sudo c_rehash /etc/ssl/certs/")
	}

	return nil
}

func createBackup() error {
	fmt.Println("Creating backup...")

	if _, err := os.Stat(caPath); os.IsNotExist(err) {
		fmt.Println("Original CA file not found, skipping backup")
		return nil
	}

	source, err := os.Open(caPath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}

	fmt.Printf("Backup created: %s\n", backupPath)
	return nil
}

func downloadCACertificates(insecure bool) error {
	fmt.Printf("Downloading CA certificates from %s...\n", caURL)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Skip certificate verification if insecure mode is enabled
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	resp, err := client.Get(caURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	file, err := os.Create(caPath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("CA certificates downloaded successfully")
	return nil
}

func rehashCertificates() error {
	fmt.Println("Rebuilding certificate hash links...")

	// Try c_rehash command
	cmd := exec.Command("c_rehash", certsDir)
	if err := cmd.Run(); err != nil {
		// If c_rehash fails, create hash links manually
		return createHashLinksManually()
	}

	fmt.Println("Certificate hash links rebuilt")
	return nil
}

func createHashLinksManually() error {
	fmt.Println("Creating hash links manually...")

	// Remove existing hash links
	pattern := filepath.Join(certsDir, "*.0")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	for _, match := range matches {
		os.Remove(match)
	}

	// Create hash links from certificate files
	certFiles := []string{
		filepath.Join(certsDir, "ca-certificates.crt"),
	}

	for _, certFile := range certFiles {
		if _, err := os.Stat(certFile); err != nil {
			continue
		}

		cmd := exec.Command("openssl", "x509", "-hash", "-noout", "-in", certFile)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		hash := string(output[:8]) // First 8 characters
		linkName := filepath.Join(certsDir, hash+".0")
		
		// Create symbolic link with relative path
		relPath, err := filepath.Rel(certsDir, certFile)
		if err != nil {
			relPath = certFile
		}

		os.Remove(linkName) // Remove existing link
		if err := os.Symlink(relPath, linkName); err != nil {
			fmt.Printf("Warning: failed to create link %s -> %s: %v\n", linkName, relPath, err)
		}
	}

	fmt.Println("Hash links created manually")
	return nil
}

func testSSLConnection() error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://www.google.com")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	
	// Simple certificate count (number of BEGIN CERTIFICATE)
	count := 0
	for i := 0; i < len(data)-len("-----BEGIN CERTIFICATE-----"); i++ {
		if string(data[i:i+len("-----BEGIN CERTIFICATE-----")]) == "-----BEGIN CERTIFICATE-----" {
			count++
		}
	}
	
	// Return dummy certificate slice
	for i := 0; i < count; i++ {
		certs = append(certs, &x509.Certificate{})
	}
	
	return certs, nil
}

func isRaspbian() bool {
	// Check /etc/os-release file
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}

	content := string(data)
	// Identify Raspbian or Raspberry Pi OS
	return contains(content, "ID=raspbian") || 
		contains(content, "ID_LIKE=raspbian") ||
		contains(content, "PRETTY_NAME=\"Raspbian") ||
		contains(content, "PRETTY_NAME=\"Raspberry Pi OS")
}

func isCAPathValid() bool {
	// Verify CA certificate path exists and is a regular file
	info, err := os.Stat(caPath)
	if err != nil {
		return false
	}

	// Ensure it's a file, not a directory
	return !info.IsDir()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 len(s) > len(substr) && 
		 (s[:len(substr)] == substr || 
		  s[len(s)-len(substr):] == substr || 
		  containsInMiddle(s, substr)))
}

func containsInMiddle(s, substr string) bool {
	for i := 1; i < len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
# Firmware Security Toolkit

A C++ toolkit for **automated firmware security analysis**.  
The tool extracts firmware images, identifies architecture, and scans for common security issues such as **hardcoded credentials, private keys, and dangerous functions**.

This project is designed for **firmware reverse engineering, IoT security analysis, and vulnerability research**.

---

# Features

### Firmware Extraction
Automatically extracts firmware using **binwalk**.

### Architecture Detection
Detects CPU architecture from firmware binaries.

### Credential Scanner
Searches firmware for **hardcoded credentials**.

Example patterns:
- admin:admin
- root:root
- password=1234

### Private Key Detector
Detects embedded private keys such as:

- RSA private keys
- SSH private keys
- TLS certificates

### Dangerous Function Detection
Identifies risky functions that may lead to vulnerabilities:

- `system()`
- `popen()`
- `strcpy()`
- `sprintf()`
- `gets()`

### Binary Scanner
Detects binary files before running analysis.

---

# Project Structure


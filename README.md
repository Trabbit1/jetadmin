# JetAdmin

JetAdmin is a Go-based tool for scanning admin panels or performing related pentesting tasks.  
This project is designed for ethical use only in your lab or authorized testing environments.

---

## Features

- Scan for common admin paths
- Lightweight and fast
- Written in Go, easy to install as a CLI tool

---

## Installation

### Option 1: Install via Go

Requires **Go 1.18+**:

```bash
go install github.com/Trabbit1/jetadmin@latest
```

Ensure $GOPATH/bin is in your PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Now you can run the tool:

```bash
jetadmin [url] <optional: custom wordlist (default: admins.txt)>
```

---

### Option 2: Build from Source

Clone the repository:

```bash
git clone https://github.com/Trabbit1/jetadmin.git
cd jetadmin
```

Build the executable:

```bash
go build -o jetadmin main.go
```

(Optional) Move it to a folder in your PATH:

```bash
sudo mv jetadmin /usr/local/bin/
```

Run:

```bash
jetadmin [url] <optional: custom wordlist (default: admins.txt)>
```

---

## Usage

```bash
jetadmin [url] <optional: custom wordlist (default: admins.txt)>
```

Example:

```bash
jetadmin https://example.com
jetadmin https://example.com custom_list.txt
```

> The second argument is optional. If not provided, it uses `admins.txt` by default.

---

## Contributing

Contributions, bug reports, and feature requests are welcome.  
Please ensure you follow ethical hacking guidelines and only test on authorized systems.

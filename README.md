# bugbounty-recon

## Introduction

This is an automated reconnaissance tool designed to enumerate assets (subdomains and URLs) of a target domain using a variety of opensource tools. It leverages parallel processing for efficiency and provides detailed logging with color-coded output for better visibility. The tool is highly configurable via a `config.json` file and includes features like subdomain enumeration, URL crawling, and validation of live endpoints.

## Prerequisites

Before using this tool, ensure the following dependencies are installed on your system:

### Required Tools

- subfinder
- assetfinder
- amass
- httpx
- waybackurls
- katana
- hakrawler

## Installing Required Tools

### 1. Install Go

```sh
$ ARCH=$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/arm64/arm64/') && \
    FILE="go1.23.6.linux-$ARCH.tar.gz" && \
    wget "https://go.dev/dl/$FILE" && \
    sudo tar -C /usr/local -xzf "$FILE"
$ sudo chown -R root:root /usr/local/go
$ mkdir -p "$HOME/go/bin" "$HOME/go/src"
$ grep -qxF 'export GOPATH=$HOME/go' $HOME/.profile || echo 'export GOPATH=$HOME/go' >> $HOME/.profile
$ grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' $HOME/.profile || echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> $HOME/.profile
$ export GOPATH=$HOME/go
$ export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```

### 2. Install Required Tools

#### subfinder

```sh
$ go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
$ sudo cp ~/go/bin/subfinder /usr/local/bin/
```

#### assetfinder

```sh
$ go install -v github.com/tomnomnom/assetfinder@latest
$ sudo cp ~/go/bin/assetfinder /usr/local/bin/
```

#### amass

```sh
$ go install -v github.com/owasp-amass/amass/v3/...@latest
$ sudo cp ~/go/bin/amass /usr/local/bin/
```

#### httpx

```sh
$ go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
$ sudo cp ~/go/bin/httpx /usr/local/bin/
```

#### waybackurls

```sh
$ go install -v github.com/tomnomnom/waybackurls@latest
$ sudo cp ~/go/bin/waybackurls /usr/local/bin/
```

#### katana

```sh
$ go install -v github.com/projectdiscovery/katana/cmd/katana@latest
$ sudo cp ~/go/bin/katana /usr/local/bin/
```

#### hakrawler

```sh
$ go install -v github.com/hakluke/hakrawler@latest
$ sudo cp ~/go/bin/hakrawler /usr/local/bin/
```

## Installation

```sh
$ git clone https://github.com/hazedic/bugbounty-recon
$ cd bugbounty-recon
$ pip install -r requirements.txt
```

**Note:** This tool has been tested for Installation on Kali Linux 2024.3

## Configuration

The tool uses a config.json file for customization. If not present, default settings are applied. 

```json
{
    "subfinder_threads": 50,
    "httpx_threads": 50,
    "httpx_timeout": 5,
    "katana_depth": 5,
    "katana_concurrency": 20,
    "exclude_extensions": "ttf,woff,woff2,svg,png,jpg,jpeg,gif,mp4,mp3,pdf,css,js,ico,eot",
    "dns_resolvers": "8.8.8.8,1.1.1.1",
    "required_tools": [
        "subfinder",
        "assetfinder",
        "amass",
        "httpx",
        "waybackurls",
        "katana",
        "hakrawler",
        "sort",
        "cut",
        "grep",
        "cat"
    ]
}
```

- `subfinder_threads`: Number of threads for `subfinder`.
- `httpx_threads`: Number of threads for `httpx`.
- `httpx_timeout`: Timeout (in seconds) for `httpx` requests.
- `katana_depth`: Crawling depth for `katana`.
- `katana_concurrency`: Concurrent requests for `katana`.
- `exclude_extensions`: File extensions to exclude from URL crawling.
- `dns_resolvers`: DNS resolvers for `amass`.

## Usage

```sh
$ python bugbounty-recon.py -h
usage: bugbounty-recon.py [-h] [-v] domain

Automated reconnaissance tool to enumerate target domain assets

positional arguments:
  domain         Target domain (e.g., example.com)

options:
  -h, --help     show this help message and exit
  -v, --verbose  Show detailed command logs
```

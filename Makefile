.PHONY: build build-linux build-darwin clean

# Default build for current OS
build:
	go build -o trivy-parser main.go

# Build for Linux (Docker containers)
build-linux:
	GOOS=linux GOARCH=amd64 go build -o trivy-parser-linux main.go

# Build for macOS
build-darwin:
	GOOS=darwin GOARCH=arm64 go build -o trivy-parser-darwin main.go

# Build for both platforms
build-all: build-linux build-darwin

# Clean build artifacts
clean:
	rm -f trivy-parser trivy-parser-linux trivy-parser-darwin
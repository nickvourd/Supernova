package Utils

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Version function
func Version() {
	Version := runtime.Version()
	Version = strings.Replace(Version, "go1.", "", -1)
	VerNumb, _ := strconv.ParseFloat(Version, 64)
	if VerNumb >= 19.1 {
	} else {
		logger := log.New(os.Stderr, "[!] ", 0)
		logger.Fatal("The version of Go is to old, please update to version 1.19.1 or later...\n")
	}
}

// GetAbsolutePath function
func GetAbsolutePath(filename string) (string, error) {
	// Get the absolute path of the file
	absolutePath, err := filepath.Abs(filename)
	if err != nil {
		return "", err
	}
	return absolutePath, nil
}

// HostIdentifier function
func HostIdentifier() string {
	// Get OS of host machine
	osName := runtime.GOOS
	var operatingSystem string

	switch osName {
	case "windows":
		operatingSystem = "Windows"
	case "linux":
		operatingSystem = "Linux"
	default:
		logger := log.New(os.Stderr, "[!] ", 0)
		logger.Fatal("Unsupported Operating System...\n")
	}

	return operatingSystem
}

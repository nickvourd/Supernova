package Utils

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// CheckGoVersio function
func CheckGoVersion() {
	version := runtime.Version()
	version = strings.Replace(version, "go1.", "", -1)
	verNumb, _ := strconv.ParseFloat(version, 64)
	if verNumb < 19.1 {
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

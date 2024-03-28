package Colors

import (
	"math/rand"
	"time"

	"github.com/fatih/color"
)

var (
	// Bold Colors
	BoldBlue    = color.New(color.FgBlue, color.Bold).SprintFunc()
	BoldRed     = color.New(color.FgRed, color.Bold).SprintFunc()
	BoldGreen   = color.New(color.FgGreen, color.Bold).SprintFunc()
	BoldYellow  = color.New(color.FgYellow, color.Bold).SprintFunc()
	BoldWhite   = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	BoldMagneta = color.New(color.FgMagenta, color.Bold).SprintFunc()
	BoldCyan    = color.New(color.FgCyan, color.Bold).SprintFunc()
)

// Define a slice containing all available color functions
var allColors = []func(a ...interface{}) string{
	BoldBlue, BoldRed, BoldGreen, BoldYellow, BoldWhite, BoldMagneta, BoldCyan,
}

// RandomColor function
// RandomColor selects a random color function from the available ones
func RandomColor() func(a ...interface{}) string {
	rand.Seed(time.Now().UnixNano())
	return allColors[rand.Intn(len(allColors))]
}

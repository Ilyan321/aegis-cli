package config

// ScanOptions holds runtime configuration flags for an Aegis scan invocation.
type ScanOptions struct {
	TargetDirectory string
	ScanStaged      bool
	ScanHistory     bool
	Verify          bool
	Format          string // "console" or "json"
	OutputFile      string
	FailOnSeverity  string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
}

// NewDefaultScanOptions initializes options with safe, high-performance defaults.
func NewDefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		TargetDirectory: ".",
		ScanStaged:      false,
		ScanHistory:     false,
		Verify:          false,
		Format:          "console",
		OutputFile:      "",
		FailOnSeverity:  "CRITICAL",
	}
}

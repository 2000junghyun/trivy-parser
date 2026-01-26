package cli

import (
	"flag"
	"fmt"
	"os"
)

// Config는 CLI 플래그로부터 파싱된 설정을 담습니다.
type Config struct {
	InputFile   string
	OutputFile  string
	RemoveCode  bool
	Preprocess  bool
	Pretty      bool
	ExportExcel bool
}

// ParseFlags는 커맨드 라인 플래그를 파싱하고 검증합니다.
func ParseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.InputFile, "input", "", "Input JSON file path (required)")
	flag.StringVar(&config.OutputFile, "output", "", "Output file or directory path (required)")
	flag.BoolVar(&config.RemoveCode, "remove-code", true, "Remove Code field (default: true)")
	flag.BoolVar(&config.Preprocess, "preprocess", false, "Preprocess: group by policy and split by target (.tf files)")
	flag.BoolVar(&config.Pretty, "pretty", false, "Format JSON with indentation")
	flag.BoolVar(&config.ExportExcel, "excel", false, "Export to Excel file (.xlsx) with Custom/Built-in sheets")

	flag.Parse()

	// 필수 인자 검증
	if config.InputFile == "" || config.OutputFile == "" {
		printUsage()
		os.Exit(1)
	}

	return config
}

// printUsage는 사용법을 출력합니다.
func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  parser -input <input.json> -output <output.json> [options]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Remove Code field only")
	fmt.Println("  parser -input result-raw.json -output result-filtered.json -pretty")
	fmt.Println()
	fmt.Println("  # Preprocess: group by policy and split by target")
	fmt.Println("  parser -input result-raw.json -output output-dir/ -preprocess -pretty")
	fmt.Println()
	fmt.Println("  # Export to Excel file")
	fmt.Println("  parser -input result-raw.json -output result.xlsx -excel")
}

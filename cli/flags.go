package cli

import (
	"flag"
	"fmt"
	"os"
)

// Config는 CLI 플래그로부터 파싱된 설정을 담습니다.
type Config struct {
	InputFile     string
	OutputFile    string
	RemoveCode    bool
	GroupByPolicy bool
	Pretty        bool
}

// ParseFlags는 커맨드 라인 플래그를 파싱하고 검증합니다.
func ParseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.InputFile, "input", "", "입력 JSON 파일 경로 (필수)")
	flag.StringVar(&config.OutputFile, "output", "", "출력 JSON 파일 경로 (필수)")
	flag.BoolVar(&config.RemoveCode, "remove-code", true, "Code 필드 제거 (기본값: true)")
	flag.BoolVar(&config.GroupByPolicy, "group-by-policy", false, "정책별로 그룹화하여 중복 제거")
	flag.BoolVar(&config.Pretty, "pretty", false, "JSON 포맷팅 (들여쓰기)")

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
	fmt.Println("사용법:")
	fmt.Println("  parser -input <input.json> -output <output.json> [options]")
	fmt.Println()
	fmt.Println("옵션:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("예시:")
	fmt.Println("  # Code 필드만 제거")
	fmt.Println("  parser -input result-raw.json -output result-filtered.json -pretty")
	fmt.Println()
	fmt.Println("  # 정책별로 그룹화 (중복 제거)")
	fmt.Println("  parser -input result-raw.json -output result-grouped.json -group-by-policy -pretty")
}

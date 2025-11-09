package main

import (
	"fmt"
	"os"
	"trivy-parser/cli"
	"trivy-parser/io"
	"trivy-parser/processor"
)

func main() {
	// 1. CLI 플래그 파싱
	config := cli.ParseFlags()

	// 2. 입력 파일 읽기
	fmt.Printf("📂 입력 파일 로드: %s\n", config.InputFile)
	data, inputSize, err := io.ReadFile(config.InputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 오류: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   크기: %.2f MB\n", inputSize)

	// 3. JSON 파싱
	fmt.Println("⚙️  JSON 파싱 중...")

	// 4. 처리 (그룹화 또는 필터링)
	var result interface{}
	if config.GroupByPolicy {
		fmt.Println("🔧 정책별로 그룹화 중...")
		result = processor.GroupByPolicy(data)
	} else if config.RemoveCode {
		fmt.Println("🔧 Code 필드 제거 중...")
		result = processor.Filter(data)
	}

	// 5. 출력 파일 저장
	outputSize, err := io.WriteFile(config.OutputFile, result, config.Pretty)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 오류: %v\n", err)
		os.Exit(1)
	}

	// 6. 통계 출력
	fmt.Printf("✅ 출력 파일 저장: %s\n", config.OutputFile)
	fmt.Printf("   크기: %.2f MB\n", outputSize)

	reduction := ((inputSize - outputSize) / inputSize) * 100
	fmt.Printf("📊 파일 크기 감소: %.1f%% (%.2f MB → %.2f MB)\n",
		reduction, inputSize, outputSize)
}

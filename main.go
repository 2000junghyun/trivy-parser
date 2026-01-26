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
	data, inputSize, err := io.ReadFile(config.InputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Input:  %s (%.2f MB)\n", config.InputFile, inputSize)

	// Excel 내보내기 처리
	if config.ExportExcel {
		if err := io.WriteExcel(config.OutputFile, data); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Output: %s (Excel format)\n", config.OutputFile)
		return
	}

	// Preprocess 모드: 그룹화 + 타겟별 분리
	if config.Preprocess {
		targetMap := processor.Preprocess(data)

		if len(targetMap) == 0 {
			fmt.Fprintf(os.Stderr, "Error: No .tf files found to process\n")
			os.Exit(1)
		}

		// 출력 디렉토리 생성
		if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// 타겟별로 파일 저장
		var totalOutputSize float64
		fileCount := 0
		var filenames []string
		for target, targetResult := range targetMap {
			targetFilename := processor.GenerateTargetFilename(config.OutputFile, target)
			outputSize, err := io.WriteFile(targetFilename, targetResult, config.Pretty)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error (%s): %v\n", target, err)
				continue
			}
			totalOutputSize += outputSize
			fileCount++
			filenames = append(filenames, targetFilename)
		}

		// 통계 출력
		fmt.Printf("Output: %d files -> %s\n", fileCount, config.OutputFile)
		for _, filename := range filenames {
			fmt.Printf("  - %s\n", filename)
		}
		reduction := ((inputSize - totalOutputSize) / inputSize) * 100
		fmt.Printf("Size reduction: %.1f%% (%.2f MB -> %.2f MB)\n",
			reduction, inputSize, totalOutputSize)
		return
	}

	// 모드가 지정되지 않은 경우 에러
	fmt.Fprintf(os.Stderr, "Error: Please specify either -excel or -preprocess mode\n")
	os.Exit(1)
}

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

	// Excel 내보내기 처리
	if config.ExportCSV {
		fmt.Println("📊 Excel 파일로 내보내는 중...")
		if err := io.WriteExcel(config.OutputFile, data); err != nil {
			fmt.Fprintf(os.Stderr, "❌ 오류: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Excel 파일 저장: %s\n", config.OutputFile)
		fmt.Printf("   - Custom 시트 (커스텀 정책)\n")
		fmt.Printf("   - Built-in 시트 (Trivy 기본 정책)\n")
		return
	}

	// 4. 처리 (그룹화 또는 필터링)
	if config.GroupByPolicy {
		fmt.Println("🔧 정책별로 그룹화 중...")
		grouped := processor.GroupByPolicy(data)

		// 5. 타겟별 파일 분리 옵션 처리
		if config.SplitByTarget {
			fmt.Println("🔧 타겟별로 파일 분리 중...")
			targetMap := processor.SplitByTarget(grouped)

			if len(targetMap) == 0 {
				fmt.Println("⚠️  분리할 타겟이 없습니다. 단일 파일로 저장합니다.")
				outputSize, err := io.WriteFile(config.OutputFile, grouped, config.Pretty)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ 오류: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("✅ 출력 파일 저장: %s\n", config.OutputFile)
				fmt.Printf("   크기: %.2f MB\n", outputSize)
			} else {
				// 출력 디렉토리 생성
				if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
					fmt.Fprintf(os.Stderr, "❌ 디렉토리 생성 실패: %v\n", err)
					os.Exit(1)
				}

				// 타겟별로 파일 저장
				var totalOutputSize float64
				fileCount := 0
				for target, targetResult := range targetMap {
					targetFilename := processor.GenerateTargetFilename(config.OutputFile, target)
					outputSize, err := io.WriteFile(targetFilename, targetResult, config.Pretty)
					if err != nil {
						fmt.Fprintf(os.Stderr, "❌ 오류 (%s): %v\n", target, err)
						continue
					}
					totalOutputSize += outputSize
					fileCount++
					fmt.Printf("✅ 저장: %s (%.2f MB)\n", targetFilename, outputSize)
				}

				// 통계 출력
				fmt.Printf("\n� 총 %d개 파일 생성\n", fileCount)
				fmt.Printf("   전체 출력 크기: %.2f MB\n", totalOutputSize)
				reduction := ((inputSize - totalOutputSize) / inputSize) * 100
				fmt.Printf("   파일 크기 감소: %.1f%% (%.2f MB → %.2f MB)\n",
					reduction, inputSize, totalOutputSize)
			}
		} else {
			// 단일 파일로 저장
			outputSize, err := io.WriteFile(config.OutputFile, grouped, config.Pretty)
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
	} else if config.RemoveCode {
		fmt.Println("🔧 Code 필드 제거 중...")
		result := processor.Filter(data)

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
}

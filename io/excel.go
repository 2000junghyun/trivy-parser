package io

import (
	"fmt"
	"strings"
	"trivy-parser/processor"

	"github.com/xuri/excelize/v2"
)

// WriteExcel은 Trivy 스캔 결과를 Excel 파일로 저장합니다.
// Custom 정책과 Built-in 정책을 각각 다른 시트에 저장합니다.
func WriteExcel(filename string, data *processor.TrivyResult) error {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	// builtin 정책과 custom 정책 분리
	customResults := []processor.Result{}
	builtinResults := []processor.Result{}

	for _, result := range data.Results {
		customMisconfigs := []processor.Misconfiguration{}
		builtinMisconfigs := []processor.Misconfiguration{}

		for _, misconfig := range result.Misconfigurations {
			if strings.HasPrefix(misconfig.Namespace, "builtin.") {
				builtinMisconfigs = append(builtinMisconfigs, misconfig)
			} else {
				customMisconfigs = append(customMisconfigs, misconfig)
			}
		}

		if len(customMisconfigs) > 0 {
			customResult := result
			customResult.Misconfigurations = customMisconfigs
			customResults = append(customResults, customResult)
		}

		if len(builtinMisconfigs) > 0 {
			builtinResult := result
			builtinResult.Misconfigurations = builtinMisconfigs
			builtinResults = append(builtinResults, builtinResult)
		}
	}

	// Custom 시트 생성 (먼저 생성)
	customSheet := "Custom"
	f.SetSheetName("Sheet1", customSheet)
	if err := writeExcelSheet(f, customSheet, customResults); err != nil {
		return fmt.Errorf("Custom 시트 작성 실패: %w", err)
	}

	// Built-in 시트 생성
	builtinSheet := "Built-in"
	_, err := f.NewSheet(builtinSheet)
	if err != nil {
		return fmt.Errorf("Built-in 시트 생성 실패: %w", err)
	}
	if err := writeExcelSheet(f, builtinSheet, builtinResults); err != nil {
		return fmt.Errorf("Built-in 시트 작성 실패: %w", err)
	}

	// 파일 저장
	if err := f.SaveAs(filename); err != nil {
		return fmt.Errorf("Excel 파일 저장 실패: %w", err)
	}

	return nil
}

// writeExcelSheet는 특정 시트에 데이터를 작성합니다.
func writeExcelSheet(f *excelize.File, sheetName string, results []processor.Result) error {
	// 헤더 스타일 정의 (Bold + 노란색 배경)
	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold: true,
		},
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"#FFFF00"}, // 노란색
			Pattern: 1,
		},
	})
	if err != nil {
		return fmt.Errorf("헤더 스타일 생성 실패: %w", err)
	}

	// 빨간색 텍스트 스타일 정의 (CRITICAL, HIGH용)
	redTextStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Color: "#FF0000", // 빨간색
		},
	})
	if err != nil {
		return fmt.Errorf("빨간색 텍스트 스타일 생성 실패: %w", err)
	}

	// 헤더 작성
	headers := []string{"Target", "Title", "Resource", "Severity", "Resolution", "StartLine", "EndLine", "PrimaryURL"}
	for i, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// 데이터 작성
	row := 2
	for _, result := range results {
		for _, misconfig := range result.Misconfigurations {
			f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), result.Target)
			f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), misconfig.Title)
			f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), misconfig.CauseMetadata.Resource)
			f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), misconfig.Severity)

			// Severity가 CRITICAL 또는 HIGH인 경우 빨간색 텍스트 적용
			severity := strings.ToUpper(misconfig.Severity)
			if severity == "CRITICAL" || severity == "HIGH" {
				severityCell := fmt.Sprintf("D%d", row)
				f.SetCellStyle(sheetName, severityCell, severityCell, redTextStyle)
			}

			f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), misconfig.Resolution)
			f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), misconfig.CauseMetadata.StartLine)
			f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), misconfig.CauseMetadata.EndLine)
			f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), misconfig.PrimaryURL)
			row++
		}
	}

	return nil
}
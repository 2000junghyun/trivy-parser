package io

import (
	"fmt"
	"strings"
	"trivy-parser/processor"

	"github.com/xuri/excelize/v2"
)

// WriteExcel은 Excel 데이터를 Excel 파일로 저장합니다.
// Custom 정책과 Built-in 정책을 각각 다른 시트에 저장합니다.
func WriteExcel(filename string, data *processor.ExcelData) error {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	// Custom 시트 생성 (먼저 생성)
	customSheet := "Custom"
	f.SetSheetName("Sheet1", customSheet)
	if err := writeExcelSheet(f, customSheet, data.CustomRows); err != nil {
		return fmt.Errorf("Custom 시트 작성 실패: %w", err)
	}

	// Built-in 시트 생성
	builtinSheet := "Built-in"
	_, err := f.NewSheet(builtinSheet)
	if err != nil {
		return fmt.Errorf("Built-in 시트 생성 실패: %w", err)
	}
	if err := writeExcelSheet(f, builtinSheet, data.BuiltinRows); err != nil {
		return fmt.Errorf("Built-in 시트 작성 실패: %w", err)
	}

	// 파일 저장
	if err := f.SaveAs(filename); err != nil {
		return fmt.Errorf("Excel 파일 저장 실패: %w", err)
	}

	return nil
}

// writeExcelSheet는 특정 시트에 데이터를 작성합니다.
func writeExcelSheet(f *excelize.File, sheetName string, rows []processor.ExcelRow) error {
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
	rowNum := 2
	for _, excelRow := range rows {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", rowNum), excelRow.Target)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", rowNum), excelRow.Title)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", rowNum), excelRow.Resource)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", rowNum), excelRow.Severity)

		// Severity가 CRITICAL 또는 HIGH인 경우 빨간색 텍스트 적용
		severity := strings.ToUpper(excelRow.Severity)
		if severity == "CRITICAL" || severity == "HIGH" {
			severityCell := fmt.Sprintf("D%d", rowNum)
			f.SetCellStyle(sheetName, severityCell, severityCell, redTextStyle)
		}

		f.SetCellValue(sheetName, fmt.Sprintf("E%d", rowNum), excelRow.Resolution)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", rowNum), excelRow.StartLine)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", rowNum), excelRow.EndLine)
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", rowNum), excelRow.PrimaryURL)
		rowNum++
	}

	return nil
}

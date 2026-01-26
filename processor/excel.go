package processor

import "strings"

// ExcelData는 Excel 파일 생성에 필요한 데이터를 담는 구조체입니다.
type ExcelData struct {
	CustomRows  []ExcelRow
	BuiltinRows []ExcelRow
}

// ExcelRow는 Excel 파일의 한 행을 나타냅니다.
type ExcelRow struct {
	Target     string
	Title      string
	Resource   string
	Severity   string
	Resolution string
	StartLine  int
	EndLine    int
	PrimaryURL string
}

// PrepareExcelData는 TrivyResult를 Excel용 데이터로 변환합니다.
// Custom 정책과 Built-in 정책을 분리하여 반환합니다.
func PrepareExcelData(data *TrivyResult) *ExcelData {
	excelData := &ExcelData{
		CustomRows:  []ExcelRow{},
		BuiltinRows: []ExcelRow{},
	}

	for _, result := range data.Results {
		for _, misconfig := range result.Misconfigurations {
			row := ExcelRow{
				Target:     result.Target,
				Title:      misconfig.Title,
				Resource:   misconfig.CauseMetadata.Resource,
				Severity:   misconfig.Severity,
				Resolution: misconfig.Resolution,
				StartLine:  misconfig.CauseMetadata.StartLine,
				EndLine:    misconfig.CauseMetadata.EndLine,
				PrimaryURL: misconfig.PrimaryURL,
			}

			// builtin 정책과 custom 정책 분리
			if strings.HasPrefix(misconfig.Namespace, "builtin.") {
				excelData.BuiltinRows = append(excelData.BuiltinRows, row)
			} else {
				excelData.CustomRows = append(excelData.CustomRows, row)
			}
		}
	}

	return excelData
}

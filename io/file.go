package io

import (
	"encoding/json"
	"fmt"
	"os"
	"trivy-parser/processor"
)

// ReadFile은 JSON 파일을 읽어 TrivyResult 구조체로 파싱합니다.
// 파일 크기(MB)도 함께 반환합니다.
func ReadFile(path string) (*processor.TrivyResult, float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("파일 읽기 실패: %w", err)
	}

	var result processor.TrivyResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, 0, fmt.Errorf("JSON 파싱 실패: %w", err)
	}

	sizeMB := float64(len(data)) / (1024 * 1024)
	return &result, sizeMB, nil
}

// WriteFile은 데이터를 JSON 형식으로 파일에 저장합니다.
// pretty가 true이면 들여쓰기를 포함합니다.
// 저장된 파일 크기(MB)를 반환합니다.
func WriteFile(path string, data interface{}, pretty bool) (float64, error) {
	var output []byte
	var err error

	if pretty {
		output, err = json.MarshalIndent(data, "", "  ")
	} else {
		output, err = json.Marshal(data)
	}

	if err != nil {
		return 0, fmt.Errorf("JSON 생성 실패: %w", err)
	}

	if err := os.WriteFile(path, output, 0644); err != nil {
		return 0, fmt.Errorf("파일 저장 실패: %w", err)
	}

	sizeMB := float64(len(output)) / (1024 * 1024)
	return sizeMB, nil
}

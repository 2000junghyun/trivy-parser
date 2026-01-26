package processor

import (
	"path/filepath"
	"strings"
)

// SplitByTarget은 그룹화된 결과를 타겟별로 분리하고, Trivy 기본 정책과 커스텀 정책으로 구분합니다.
// 각 타겟(파일)별로 두 개의 GroupedTrivyResult를 생성합니다:
// - [TV] prefix: Trivy 기본 정책 (builtin.*, AVD-*)
// - [KB] prefix: 커스텀 정책 (user.*, USER-*)
// .tf 파일만 처리하고 디렉토리 등은 스킵합니다.
func SplitByTarget(input *GroupedTrivyResult) map[string]*GroupedTrivyResult {
	targetMap := make(map[string]*GroupedTrivyResult)

	for _, result := range input.Results {
		// 타겟이 비어있거나 "."인 경우는 스킵
		if result.Target == "" || result.Target == "." {
			continue
		}

		// .tf 파일이 아니면 스킵
		if filepath.Ext(result.Target) != ".tf" {
			continue
		}

		// Trivy 기본 정책과 커스텀 정책으로 Misconfiguration 분리
		trivyMisconfigs := []GroupedMisconfiguration{}
		customMisconfigs := []GroupedMisconfiguration{}

		for _, misconfig := range result.Misconfigurations {
			if isBuiltinPolicy(misconfig) {
				trivyMisconfigs = append(trivyMisconfigs, misconfig)
			} else {
				customMisconfigs = append(customMisconfigs, misconfig)
			}
		}

		// Trivy 기본 정책 결과 저장 (TV prefix)
		if len(trivyMisconfigs) > 0 {
			trivyKey := "[TV]" + result.Target
			if _, exists := targetMap[trivyKey]; !exists {
				targetMap[trivyKey] = &GroupedTrivyResult{
					SchemaVersion:   input.SchemaVersion,
					CreatedAt:       input.CreatedAt,
					ArtifactName:    input.ArtifactName,
					ArtifactType:    input.ArtifactType,
					SeveritySummary: &SeveritySummary{},
					Results:         []GroupedResult{},
				}
			}

			trivyResult := result
			trivyResult.Misconfigurations = trivyMisconfigs
			trivyResult.MisconfSummary.Failures = len(trivyMisconfigs)
			targetMap[trivyKey].Results = append(targetMap[trivyKey].Results, trivyResult)
		}

		// 커스텀 정책 결과 저장 (KB prefix)
		if len(customMisconfigs) > 0 {
			customKey := "[KB]" + result.Target
			if _, exists := targetMap[customKey]; !exists {
				targetMap[customKey] = &GroupedTrivyResult{
					SchemaVersion:   input.SchemaVersion,
					CreatedAt:       input.CreatedAt,
					ArtifactName:    input.ArtifactName,
					ArtifactType:    input.ArtifactType,
					SeveritySummary: &SeveritySummary{},
					Results:         []GroupedResult{},
				}
			}

			customResult := result
			customResult.Misconfigurations = customMisconfigs
			customResult.MisconfSummary.Failures = len(customMisconfigs)
			targetMap[customKey].Results = append(targetMap[customKey].Results, customResult)
		}
	}

	// 각 타겟별로 심각도 카운트 계산
	for _, targetResult := range targetMap {
		calculateSeveritySummary(targetResult)
	}

	return targetMap
}

// isBuiltinPolicy는 해당 정책이 Trivy 기본 정책인지 확인합니다.
func isBuiltinPolicy(misconfig GroupedMisconfiguration) bool {
	// Namespace가 builtin.으로 시작하면 기본 정책, user.로 시작하면 커스텀 정책
	return strings.HasPrefix(misconfig.Namespace, "builtin.")
}

// calculateSeveritySummary는 GroupedTrivyResult의 심각도별 카운트를 계산합니다.
func calculateSeveritySummary(result *GroupedTrivyResult) {
	summary := &SeveritySummary{}

	for _, res := range result.Results {
		for _, misconfig := range res.Misconfigurations {
			switch strings.ToUpper(misconfig.Severity) {
			case "CRITICAL":
				summary.Critical++
			case "HIGH":
				summary.High++
			case "MEDIUM":
				summary.Medium++
			case "LOW":
				summary.Low++
			}
		}
	}

	result.SeveritySummary = summary
}

// GenerateTargetFilename은 타겟 이름으로부터 안전한 파일명을 생성합니다.
// 예: "test-dir/test-sub-dir/test-05.tf" -> "test-dir%test-sub-dir%test-05.json"
func GenerateTargetFilename(outputDir, target string) string {
	// 타겟에서 확장자 제거
	targetExt := filepath.Ext(target)
	targetBase := strings.TrimSuffix(target, targetExt)

	// 슬래시를 %로 대체
	filename := strings.ReplaceAll(targetBase, "/", "%")
	filename = strings.ReplaceAll(filename, "\\", "%")

	// .json 확장자 추가
	filename += ".json"

	// 출력 디렉토리와 결합
	return filepath.Join(outputDir, filename)
}
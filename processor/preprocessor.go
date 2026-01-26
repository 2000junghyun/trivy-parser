package processor

import (
	"path/filepath"
	"strings"
)

// Preprocess는 Trivy 스캔 결과를 그룹화하고 타겟별로 분리하는 전처리를 수행합니다.
// 1. 동일한 정책 ID의 misconfiguration들을 그룹화
// 2. 타겟(.tf 파일)별로 분리
// 3. Trivy 기본 정책([TV])과 커스텀 정책([KB])으로 구분
// 4. 각 타겟별로 심각도 요약 계산
func Preprocess(input *TrivyResult) map[string]*GroupedTrivyResult {
	// 1단계: 정책별 그룹화
	grouped := groupByPolicyInternal(input)

	// 2단계: 타겟별 분리 및 정책 유형별 분류
	targetMap := splitByTargetInternal(grouped)

	return targetMap
}

// groupByPolicyInternal은 동일한 정책 ID를 가진 misconfiguration들을 그룹화합니다.
func groupByPolicyInternal(input *TrivyResult) *GroupedTrivyResult {
	grouped := &GroupedTrivyResult{
		SchemaVersion: input.SchemaVersion,
		CreatedAt:     input.CreatedAt,
		ArtifactName:  input.ArtifactName,
		ArtifactType:  input.ArtifactType,
		Results:       make([]GroupedResult, len(input.Results)),
	}

	for i, result := range input.Results {
		// 정책 ID별로 그룹화하기 위한 맵
		policyMap := make(map[string]*GroupedMisconfiguration)

		for _, misconf := range result.Misconfigurations {
			// 정책 ID를 키로 사용
			policyKey := misconf.ID

			if existing, exists := policyMap[policyKey]; exists {
				// 이미 존재하는 정책에 violation 추가
				existing.Violations = append(existing.Violations, Violation{
					Resource:  misconf.CauseMetadata.Resource,
					Provider:  misconf.CauseMetadata.Provider,
					Service:   misconf.CauseMetadata.Service,
					StartLine: misconf.CauseMetadata.StartLine,
					EndLine:   misconf.CauseMetadata.EndLine,
					Message:   misconf.Message,
				})
			} else {
				// 새로운 정책 추가
				policyMap[policyKey] = &GroupedMisconfiguration{
					ID:          misconf.ID,
					Title:       misconf.Title,
					Description: misconf.Description,
					Namespace:   misconf.Namespace,
					Resolution:  misconf.Resolution,
					Severity:    misconf.Severity,
					PrimaryURL:  misconf.PrimaryURL,
					Status:      misconf.Status,
					Violations: []Violation{
						{
							Resource:  misconf.CauseMetadata.Resource,
							Provider:  misconf.CauseMetadata.Provider,
							Service:   misconf.CauseMetadata.Service,
							StartLine: misconf.CauseMetadata.StartLine,
							EndLine:   misconf.CauseMetadata.EndLine,
							Message:   misconf.Message,
						},
					},
				}
			}
		}

		// 맵을 슬라이스로 변환
		groupedMisconfs := make([]GroupedMisconfiguration, 0, len(policyMap))
		for _, policy := range policyMap {
			groupedMisconfs = append(groupedMisconfs, *policy)
		}

		// GroupedResult 생성
		groupedResult := GroupedResult{
			Target: result.Target,
			Class:  result.Class,
			Type:   result.Type,
			MisconfSummary: MisconfSummary{
				Successes: result.MisconfSummary.Successes,
				Failures:  len(groupedMisconfs),
			},
			Misconfigurations: groupedMisconfs,
		}

		grouped.Results[i] = groupedResult
	}

	return grouped
}

// splitByTargetInternal은 그룹화된 결과를 타겟별로 분리하고, Trivy 기본 정책과 커스텀 정책으로 구분합니다.
func splitByTargetInternal(input *GroupedTrivyResult) map[string]*GroupedTrivyResult {
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
			if isBuiltinPolicyInternal(misconfig) {
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
		calculateSeveritySummaryInternal(targetResult)
	}

	return targetMap
}

// isBuiltinPolicyInternal은 해당 정책이 Trivy 기본 정책인지 확인합니다.
func isBuiltinPolicyInternal(misconfig GroupedMisconfiguration) bool {
	return strings.HasPrefix(misconfig.Namespace, "builtin.")
}

// calculateSeveritySummaryInternal은 GroupedTrivyResult의 심각도별 카운트를 계산합니다.
func calculateSeveritySummaryInternal(result *GroupedTrivyResult) {
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

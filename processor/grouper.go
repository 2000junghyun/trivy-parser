package processor

// GroupByPolicy는 동일한 정책 ID를 가진 misconfiguration들을 그룹화합니다.
// 같은 정책에 대한 여러 위반 사항을 Violations 배열로 통합합니다.
func GroupByPolicy(input *TrivyResult) *GroupedTrivyResult {
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

		// MisconfSummary 업데이트 (그룹화된 수로)
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
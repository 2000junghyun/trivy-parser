package processor

// Filter는 Trivy 스캔 결과에서 불필요한 필드를 제거합니다.
// Code, Type, AVDID, Query, References 필드가 제거됩니다.
func Filter(input *TrivyResult) *FilteredTrivyResult {
	filtered := &FilteredTrivyResult{
		SchemaVersion: input.SchemaVersion,
		CreatedAt:     input.CreatedAt,
		ArtifactName:  input.ArtifactName,
		ArtifactType:  input.ArtifactType,
		Results:       make([]FilteredResult, len(input.Results)),
	}

	for i, result := range input.Results {
		filteredResult := FilteredResult{
			Target:            result.Target,
			Class:             result.Class,
			Type:              result.Type,
			MisconfSummary:    result.MisconfSummary,
			Misconfigurations: make([]FilteredMisconfiguration, len(result.Misconfigurations)),
		}

		for j, misconf := range result.Misconfigurations {
			filteredMisconf := FilteredMisconfiguration{
				ID:          misconf.ID,
				Title:       misconf.Title,
				Description: misconf.Description,
				Message:     misconf.Message,
				Namespace:   misconf.Namespace,
				Resolution:  misconf.Resolution,
				Severity:    misconf.Severity,
				PrimaryURL:  misconf.PrimaryURL,
				Status:      misconf.Status,
				CauseMetadata: FilteredCauseMetadata{
					Resource:    misconf.CauseMetadata.Resource,
					Provider:    misconf.CauseMetadata.Provider,
					Service:     misconf.CauseMetadata.Service,
					StartLine:   misconf.CauseMetadata.StartLine,
					EndLine:     misconf.CauseMetadata.EndLine,
					Occurrences: misconf.CauseMetadata.Occurrences,
				},
			}
			filteredResult.Misconfigurations[j] = filteredMisconf
		}

		filtered.Results[i] = filteredResult
	}

	return filtered
}
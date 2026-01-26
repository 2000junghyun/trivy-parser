package processor

// Trivy 스캔 결과 구조체 정의
type TrivyResult struct {
	SchemaVersion int      `json:"SchemaVersion"`
	CreatedAt     string   `json:"CreatedAt"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	MisconfSummary    MisconfSummary     `json:"MisconfSummary"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations,omitempty"`
}

type MisconfSummary struct {
	Successes int `json:"Successes"`
	Failures  int `json:"Failures"`
}

type Misconfiguration struct {
	Type          string        `json:"Type"`
	ID            string        `json:"ID"`
	AVDID         string        `json:"AVDID"`
	Title         string        `json:"Title"`
	Description   string        `json:"Description"`
	Message       string        `json:"Message"`
	Namespace     string        `json:"Namespace"`
	Query         string        `json:"Query"`
	Resolution    string        `json:"Resolution"`
	Severity      string        `json:"Severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"References"`
	Status        string        `json:"Status"`
	CauseMetadata CauseMetadata `json:"CauseMetadata"`
}

type CauseMetadata struct {
	Resource    string       `json:"Resource"`
	Provider    string       `json:"Provider"`
	Service     string       `json:"Service"`
	StartLine   int          `json:"StartLine"`
	EndLine     int          `json:"EndLine"`
	Code        *CodeBlock   `json:"Code,omitempty"`
	Occurrences []Occurrence `json:"Occurrences,omitempty"`
}

type CodeBlock struct {
	Lines []CodeLine `json:"Lines"`
}

type CodeLine struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

type Occurrence struct {
	Resource string   `json:"Resource"`
	Filename string   `json:"Filename"`
	Location Location `json:"Location"`
}

type Location struct {
	StartLine int `json:"StartLine"`
	EndLine   int `json:"EndLine"`
}

// 필터링된 결과 구조체 (Code, Type, AVDID, Query, References 필드 제외)
type FilteredMisconfiguration struct {
	ID            string                `json:"ID"`
	Title         string                `json:"Title"`
	Description   string                `json:"Description"`
	Message       string                `json:"Message"`
	Namespace     string                `json:"Namespace"`
	Resolution    string                `json:"Resolution"`
	Severity      string                `json:"Severity"`
	PrimaryURL    string                `json:"PrimaryURL"`
	Status        string                `json:"Status"`
	CauseMetadata FilteredCauseMetadata `json:"CauseMetadata"`
}

type FilteredCauseMetadata struct {
	Resource    string       `json:"Resource"`
	Provider    string       `json:"Provider"`
	Service     string       `json:"Service"`
	StartLine   int          `json:"StartLine"`
	EndLine     int          `json:"EndLine"`
	Occurrences []Occurrence `json:"Occurrences,omitempty"`
}

type FilteredResult struct {
	Target            string                     `json:"Target"`
	Class             string                     `json:"Class"`
	Type              string                     `json:"Type"`
	MisconfSummary    MisconfSummary             `json:"MisconfSummary"`
	Misconfigurations []FilteredMisconfiguration `json:"Misconfigurations,omitempty"`
}

type FilteredTrivyResult struct {
	SchemaVersion int              `json:"SchemaVersion"`
	CreatedAt     string           `json:"CreatedAt"`
	ArtifactName  string           `json:"ArtifactName"`
	ArtifactType  string           `json:"ArtifactType"`
	Results       []FilteredResult `json:"Results"`
}

// 그룹화된 결과 구조체 (Type, AVDID, Query, References 제외)
type GroupedMisconfiguration struct {
	ID          string      `json:"ID"`
	Title       string      `json:"Title"`
	Description string      `json:"Description"`
	Namespace   string      `json:"Namespace"`
	Resolution  string      `json:"Resolution"`
	Severity    string      `json:"Severity"`
	PrimaryURL  string      `json:"PrimaryURL"`
	Status      string      `json:"Status"`
	Violations  []Violation `json:"Violations"`
}

type Violation struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Message   string `json:"Message"`
}

type GroupedResult struct {
	Target            string                    `json:"Target"`
	Class             string                    `json:"Class"`
	Type              string                    `json:"Type"`
	MisconfSummary    MisconfSummary            `json:"MisconfSummary"`
	Misconfigurations []GroupedMisconfiguration `json:"Misconfigurations,omitempty"`
}

type GroupedTrivyResult struct {
	SchemaVersion   int              `json:"SchemaVersion"`
	CreatedAt       string           `json:"CreatedAt"`
	ArtifactName    string           `json:"ArtifactName"`
	ArtifactType    string           `json:"ArtifactType"`
	SeveritySummary *SeveritySummary `json:"SeveritySummary,omitempty"`
	Results         []GroupedResult  `json:"Results"`
}

// SeveritySummary는 심각도별 검출 개수를 나타냅니다.
type SeveritySummary struct {
	Critical int `json:"CRITICAL"`
	High     int `json:"HIGH"`
	Medium   int `json:"MEDIUM"`
	Low      int `json:"LOW"`
}
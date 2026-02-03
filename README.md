# Overview

Trivy Parser는 Trivy `--format json` 출력 결과를 후처리하는 **Go 기반 포스트 프로세서**입니다.
용량이 큰 원본 스캔 결과를 검토/공유하기 쉬운 형태로 변환합니다.

지원하는 모드는 두 가지입니다:

- **Preprocess 모드**: 정책 ID 기준으로 결과를 그룹화하고, Terraform 타겟(`.tf`)별로 분리하며, **빌트인** 정책과 **커스텀** 정책을 분리합니다.
- **Excel 내보내기 모드**: 결과를 `.xlsx` 파일로 내보냅니다(시트 2개: `Custom`, `Built-in`). 필터링/정렬/리포팅에 적합합니다.

## Tech Stack

- **Language**: Go (`go.mod` 참고)
- **Libraries**: Excel 생성을 위해 `github.com/xuri/excelize/v2` 사용
- **Environment**: 단일 바이너리, 크로스 플랫폼(Linux/macOS/Windows)

## Directory Structure

```
.
├── cli/
│   └── flags.go              # CLI 플래그 파싱
│
├── io/
│   ├── file.go               # JSON 읽기/쓰기
│   └── excel.go              # Excel 파일 출력(I/O만 담당)
│
├── processor/
│   ├── types.go              # Trivy / 그룹화 결과 구조체 정의
│   ├── preprocessor.go       # preprocess 모드의 그룹화 + 분리 로직
│   └── excel.go              # TrivyResult -> ExcelData 변환
│
├── test-input/
│   └── result-01.json         # Trivy JSON 샘플
│
├── test-output/
│   ├── excel/                 # Excel 출력 예시
│   └── preprocess/            # preprocess 출력 예시
│
├── main.go                    # 엔트리포인트
├── Makefile                   # 빌드 헬퍼
└── go.mod
```

## How It Works

### 1. Preprocess Mode (`processor/preprocessor.go`)

Preprocess 모드는 3단계로 동작합니다:

1. **정책 ID 기준 그룹화**
- 각 Trivy `Result`에 대해 misconfiguration을 `ID` 기준으로 그룹화합니다.
- 그룹화된 정책에는 `Violations` 배열(resource/line/message)이 포함되며, 정책 메타데이터 중복을 줄입니다.
2. **타겟(`.tf`) 기준 분리**
- `Target` 값이 `.tf`로 끝나는 항목만 처리합니다.
- 타겟별로 결과를 개별 파일로 분리합니다.
3. **빌트인 vs 커스텀 분리**
- 빌트인 정책: `Namespace`가 `builtin.`으로 시작
- 커스텀 정책: 그 외(예: `user.*`)

출력 파일명은 정책 유형을 나타내는 prefix를 사용합니다:

- `builtin-...json`
- `custom-...json`

파일명은 Trivy 타겟에서 아래 규칙으로 생성됩니다:

- 확장자 제거(예: `main.tf` -> `main`)
- 경로 구분자를 `%`로 치환(예: `modules/vpc/main.tf` -> `modules%vpc%main`)

출력 예시:

- `builtin-main.json`
- `custom-main.json`
- `builtin-modules%vpc%main.json`

### 2. Excel Export Mode (`processor/excel.go` + `io/excel.go`)

Excel 모드는 책임을 명확히 분리해 구현되어 있습니다:

- **변환(`processor/excel.go`)**: `TrivyResult`를 평탄화된 `ExcelData` 행으로 변환하고, 빌트인/커스텀을 분리합니다.
- **출력(`io/excel.go`)**: 아래 두 시트를 가진 `.xlsx` 파일을 생성합니다.
    - `Custom`
    - `Built-in`

Excel 출력 컬럼은 다음과 같습니다:

- Target, Title, Resource, Severity, Resolution, StartLine, EndLine, PrimaryURL

스타일링:

- 헤더 행: Bold + 노란색 배경
- Severity 셀: `CRITICAL`, `HIGH`는 빨간색 텍스트

## How to Run Locally

### 1. Build

```bash
go build -o trivy-parser
```

또는 Makefile 사용:

```bash
make build
```

### 2. Preprocess mode

```bash
./trivy-parser \\
  -input ./test-input/result-01.json \\
  -output ./test-output/preprocess/ \\
  -preprocess \\
  -pretty
```

### 3. Excel export mode

```bash
./trivy-parser \\
  -input ./test-input/result-01.json \\
  -output ./test-output/excel/result.xlsx \\
  -excel
```

참고: Excel 모드에서는 출력 디렉토리가 미리 존재해야 합니다.

## CLI Options

| Flag | Default | Description |
| --- | --- | --- |
| `-input` | (required) | Trivy JSON 결과 파일 경로 |
| `-output` | (required) | 출력 `.xlsx` 경로(Excel 모드) 또는 출력 디렉토리(preprocess 모드) |
| `-excel` | `false` | `Custom` / `Built-in` 시트를 가진 `.xlsx`로 내보내기 |
| `-preprocess` | `false` | 결과를 그룹화하고 `.tf` 타겟 기준으로 분리 |
| `-pretty` | `false` | preprocess 모드 JSON을 들여쓰기 형식으로 출력 |
- `excel` 또는 `preprocess` 중 하나는 반드시 지정해야 합니다.

## Features / Main Logic

- **정책 그룹화**: 정책 메타데이터 중복을 제거해 용량을 줄입니다.
- **타겟 기반 분리**: Terraform 파일 단위로 개선/조치하기 쉬운 형태로 분리합니다.
- **빌트인 vs 커스텀 분리**: Trivy 빌트인 정책과 조직 커스텀 정책을 명확히 구분합니다.
- **심각도 요약**: preprocess 결과에 파일별 심각도(CRITICAL/HIGH/MEDIUM/LOW) 카운트가 포함됩니다.
- **Excel 리포팅**: 핵심 필드만 포함한 2시트 스프레드시트로 내보냅니다.

## Motivation / Impact

- **빠른 리뷰**: Excel 출력은 비개발자도 쉽게 필터/정렬하며 검토할 수 있습니다.
- **명확한 오너십**: preprocess 모드로 Terraform 파일별 담당자에게 이슈를 배분하기 쉽습니다.
- **아티팩트 경량화**: 그룹화된 JSON은 CI/CD 아티팩트 저장/전송 비용을 줄입니다.
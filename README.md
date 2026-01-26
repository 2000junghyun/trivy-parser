# Trivy Parser

Trivy 스캔 결과 JSON 파일을 최적화하는 Go 기반 파서입니다. 불필요한 필드를 제거하고, 중복된 정책을 그룹화하여 파일 크기를 대폭 줄입니다.

## 📋 주요 기능

### 1. 필터링 모드 (기본)
- **제거되는 필드**: `Code`, `Type`, `AVDID`, `Query`, `References`
- **크기 감소**: 약 75-80%
- **사용 사례**: 파일 크기는 줄이되 모든 개별 위반 사항을 유지하고 싶을 때

### 2. 그룹화 모드
- **기능**: 동일한 정책 ID의 위반 사항을 하나로 통합
- **크기 감소**: 약 85-90%
- **사용 사례**: 정책별 요약이 필요하고 최대한 파일 크기를 줄이고 싶을 때
- **구조**: 각 정책마다 `Violations` 배열에 모든 위반 리소스 정보 포함

### 3. 타겟별 파일 분리 모드
- **기능**: 그룹화된 결과를 타겟(파일)별로 개별 파일로 분리하고, 정책 유형별로 구분
- **정책 분류**:
  - `[TV]` prefix: Trivy 기본 정책 (Namespace가 `builtin.`으로 시작)
  - `[KB]` prefix: 커스텀 정책 (Namespace가 `user.`로 시작)
- **사용 사례**: 각 Terraform 파일별로 검출 결과를 따로 확인하고, 기본 정책과 커스텀 정책을 분리하여 관리하고 싶을 때
- **추가 기능**: 각 파일 상단에 심각도별 검출 개수 요약 (CRITICAL, HIGH, MEDIUM, LOW) 포함

### 4. Excel 내보내기 모드
- **기능**: 스캔 결과를 Excel 파일(.xlsx)로 내보내기
- **시트 구조**:
  - `Custom` 시트: 커스텀 정책 (Namespace가 `user.`로 시작)
  - `Built-in` 시트: Trivy 기본 정책 (Namespace가 `builtin.`으로 시작)
- **포함 필드**: Target, Title, Resource, Severity, Resolution, StartLine, EndLine, PrimaryURL
- **스타일링**:
  - 헤더 행: Bold + 노란색 배경
  - Severity가 CRITICAL/HIGH인 경우: 빨간색 텍스트
- **사용 사례**: 검출 결과를 Excel에서 필터링, 정렬하여 분석하거나 리포트를 작성할 때

## 🏗️ 프로젝트 구조

```
trivy-parser/
├── main.go              # 진입점
├── processor/           # 비즈니스 로직
│   ├── types.go        # 데이터 구조체 정의 (SeveritySummary 포함)
│   ├── filter.go       # 필터링 로직
│   ├── grouper.go      # 그룹화 로직
│   └── splitter.go     # 타겟별 분리 로직
├── io/                  # 파일 입출력
│   ├── file.go         # JSON 읽기/쓰기
│   └── excel.go        # Excel 파일 생성
├── cli/                 # 커맨드라인 인터페이스
│   └── flags.go        # 플래그 정의 및 검증
└── README.md
```

## 🚀 빌드

```bash
go build -o trivy-parser
```

## 💻 사용법

### 기본 필터링 (Code 필드 제거)

```bash
./trivy-parser -input result-raw.json -output result-filtered.json
```

### 필터링 + 가독성 좋은 JSON 출력

```bash
./trivy-parser -input result-raw.json -output result-filtered.json -pretty
```

### 그룹화 모드 (정책별 통합)

```bash
./trivy-parser -input result-raw.json -output result-grouped.json -grouped -pretty
```

### 타겟별 파일 분리 모드 (그룹화 + 파일 분리 + 정책 유형별 분류)

```bash
./trivy-parser -input result-raw.json -output output-directory/ -grouped -splitted -pretty
```

이 명령어는 각 타겟(.tf 파일)별로 2개의 파일을 생성합니다:
- `[TV]파일명.json`: Trivy 기본 정책 검출 결과
- `[KB]파일명.json`: 커스텀 정책 검출 결과

> **주의**: `-splitted` 플래그를 사용할 때는 `-output`에 디렉토리 경로를 지정해야 합니다.

### Excel 파일로 내보내기

```bash
./trivy-parser -input result-raw.json -output result.xlsx -excel
```

이 명령어는 하나의 Excel 파일에 2개의 시트를 생성합니다:
- `Custom` 시트: 커스텀 정책 검출 결과
- `Built-in` 시트: Trivy 기본 정책 검출 결과

## 📝 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-input` | (필수) | 입력 JSON 파일 경로 |
| `-output` | (필수) | 출력 JSON 파일 경로 또는 디렉토리 경로 (`-splitted` 사용 시) |
| `-remove-code` | `true` | Code 필드 제거 여부 |
| `-grouped` | `false` | 정책별로 그룹화하여 중복 제거 |
| `-splitted` | `false` | 타겟(파일)별로 결과를 개별 파일로 분리 (`-grouped`와 함께 사용) |
| `-pretty` | `false` | JSON 포맷팅 (들여쓰기) |
| `-excel` | `false` | Excel 파일(.xlsx)로 내보내기 (Custom/Built-in 시트 분리) |

## 📊 성능

실제 Trivy 스캔 결과를 기준으로:

### 예시 1 (157KB, 43개 misconfiguration)

| 모드 | 출력 크기 | 감소율 | Misconfiguration 수 |
|------|-----------|--------|---------------------|
| 원본 | 157 KB | - | 43개 (중복 포함) |
| 필터링 | 38 KB | 75.8% ↓ | 43개 (유지) |
| 그룹화 | 19 KB | 87.9% ↓ | 11개 (정책별 통합) |

### 예시 2 (490KB, 6개 타겟, 기본 정책 + 커스텀 정책)

| 모드 | 출력 크기 | 감소율 | 출력 파일 수 |
|------|-----------|--------|-------------|
| 원본 | 490 KB | - | 1개 |
| 그룹화 + 타겟별 분리 | 67 KB | 86.3% ↓ | 8개 (4개 타겟 × 2 분류) |

각 타겟별로 2개의 파일이 생성됩니다:
- `[TV]` prefix: Trivy 기본 정책 검출 결과
- `[KB]` prefix: 커스텀 정책 검출 결과

> **참고**: 타겟별 분리 모드는 `.tf` 확장자를 가진 파일만 처리하며, 디렉토리는 자동으로 스킵됩니다.

## 🔍 출력 구조

### 필터링 모드 출력 예시

```json
{
  "Misconfigurations": [
    {
      "ID": "AVD-AWS-0088",
      "Title": "Unencrypted S3 bucket.",
      "Description": "S3 Buckets should be encrypted...",
      "Message": "Bucket does not have encryption enabled",
      "Namespace": "builtin.aws.s3.aws0088",
      "Resolution": "Configure bucket encryption",
      "Severity": "HIGH",
      "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0088",
      "Status": "FAIL",
      "CauseMetadata": {
        "Resource": "aws_s3_bucket.my_bucket",
        "Provider": "AWS",
        "Service": "s3",
        "StartLine": 28,
        "EndLine": 34
      }
    }
  ]
}
```

### 그룹화 모드 출력 예시

```json
{
  "Misconfigurations": [
    {
      "ID": "AVD-AWS-0088",
      "Title": "Unencrypted S3 bucket.",
      "Description": "S3 Buckets should be encrypted...",
      "Namespace": "builtin.aws.s3.aws0088",
      "Resolution": "Configure bucket encryption",
      "Severity": "HIGH",
      "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0088",
      "Status": "FAIL",
      "Violations": [
        {
          "Resource": "aws_s3_bucket.bucket1",
          "Provider": "AWS",
          "Service": "s3",
          "StartLine": 28,
          "EndLine": 34,
          "Message": "Bucket does not have encryption enabled"
        },
        {
          "Resource": "aws_s3_bucket.bucket2",
          "Provider": "AWS",
          "Service": "s3",
          "StartLine": 45,
          "EndLine": 51,
          "Message": "Bucket does not have encryption enabled"
        }
      ]
    }
  ]
}
```

### 타겟별 분리 모드 출력 예시

각 타겟별로 2개의 파일이 생성됩니다 (경로의 슬래시가 `%`로 대체됨):
- `[TV]test-dir%test-sub-dir%test-05.json`: Trivy 기본 정책
- `[KB]test-dir%test-sub-dir%test-05.json`: 커스텀 정책

#### [TV] Trivy 기본 정책 파일 예시

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2025-11-12T16:15:14.949475+09:00",
  "ArtifactName": "storage/1/mr-23",
  "ArtifactType": "filesystem",
  "SeveritySummary": {
    "CRITICAL": 0,
    "HIGH": 6,
    "MEDIUM": 1,
    "LOW": 2
  },
  "Results": [
    {
      "Target": "test-dir/test-sub-dir/test-05.tf",
      "Class": "config",
      "Type": "terraform",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 9
      },
      "Misconfigurations": [
        {
          "ID": "AVD-AWS-0088",
          "Title": "Unencrypted S3 bucket.",
          "Namespace": "builtin.aws.s3.aws0088",
          ...
        }
      ]
    }
  ]
}
```

#### [KB] 커스텀 정책 파일 예시

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2025-11-12T16:15:14.949475+09:00",
  "ArtifactName": "storage/1/mr-23",
  "ArtifactType": "filesystem",
  "SeveritySummary": {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0
  },
  "Results": [
    {
      "Target": "test-dir/test-sub-dir/test-05.tf",
      "Class": "config",
      "Type": "terraform",
      "MisconfSummary": {
        "Successes": 0,
        "Failures": 1
      },
      "Misconfigurations": [
        {
          "ID": "USER-003",
          "Title": "S3 bucket must use KMS encryption",
          "Namespace": "user.aws.s3.encryption",
          ...
        }
      ]
    }
  ]
}
```

> **참고**: 
> - `SeveritySummary`는 타겟별 분리 모드에서만 포함되며, 해당 파일에서 검출된 심각도별 정책 개수를 보여줍니다.
> - 정책 분류는 `Namespace` 필드를 기준으로 합니다 (`builtin.` vs `user.`).

## 🔧 Trivy와 통합 사용

```bash
# 1. Trivy로 스캔
trivy config --format json --output raw-result.json terraform-source/

# 2. Parser로 최적화
./trivy-parser -input raw-result.json -output filtered-result.json -pretty

# 3. 그룹화 모드로
./trivy-parser -input raw-result.json -output grouped-result.json -grouped -pretty

# 4. 타겟별 파일 분리 (각 .tf 파일별로 개별 JSON 생성)
./trivy-parser -input raw-result.json -output results/ -grouped -splitted -pretty

# 5. Excel 파일로 내보내기 (스프레드시트로 분석)
./trivy-parser -input raw-result.json -output result.xlsx -excel
```

## 🎯 사용 사례

### Case 1: CI/CD 파이프라인에서 아티팩트 저장
- 원본은 157KB이지만 필터링 후 38KB로 저장
- 스토리지 비용 절감 및 다운로드 시간 단축

### Case 2: 정책 위반 리포트 생성
- 그룹화 모드로 19KB 파일 생성
- 정책별로 정리되어 리뷰가 쉬움
- 43개 항목 → 11개 정책 그룹으로 간소화

### Case 3: 대시보드 데이터 소스
- 불필요한 Code 필드 제거로 파싱 속도 향상
- JSON 크기 감소로 네트워크 전송 부하 감소

### Case 4: 파일별 보안 검토 (정책 유형별 분리)
- 타겟별 분리 모드로 각 Terraform 파일의 보안 이슈를 개별적으로 관리
- 정책 유형별로 파일을 분리하여 관리:
  - `[TV]` 파일: Trivy 기본 정책 검출 결과 (업계 표준 보안 정책)
  - `[KB]` 파일: 커스텀 정책 검출 결과 (조직 특화 정책)
- 파일 상단의 `SeveritySummary`로 각 정책 유형별 심각도를 한눈에 파악
- 예: `main.tf`는 `[TV]main.json`과 `[KB]main.json`으로 분리

### Case 5: Excel 기반 분석 및 리포트
- Excel 내보내기 모드로 스프레드시트 형식으로 변환
- Excel의 필터, 정렬, 피벗 테이블 기능을 활용하여 데이터 분석
- 시각적 스타일링으로 중요 정보 강조:
  - CRITICAL/HIGH severity는 빨간색으로 표시되어 즉시 식별 가능
  - 헤더는 노란색 배경으로 구분이 명확
- Custom 정책과 Built-in 정책이 별도 시트로 분리되어 관리 용이
- 팀 공유 및 리포트 작성이 쉬움

## 🛠️ 개발 정보

### 리팩토링 히스토리
- **이전**: 단일 파일 (main.go, 386 lines)
- **현재**: 모듈화된 구조 (6 files, 각 50-158 lines)
- **개선 사항**: 
  - 관심사 분리 (데이터 모델, 비즈니스 로직, I/O, CLI)
  - 확장성 향상 (새 처리 모드 추가 용이)
  - 테스트 가능성 증가

### 백업 파일
프로젝트 디렉토리에 리팩토링 전 백업이 있습니다:
- `main.go.old`: 리팩토링 전 원본 코드

## � 사용된 도구 및 패키지

### Go 버전
- **Go 1.24.0**

### 표준 라이브러리
- `encoding/json`: JSON 파싱 및 직렬화
- `flag`: 커맨드라인 플래그 처리
- `os`: 파일 시스템 작업
- `fmt`: 포맷팅 및 출력
- `path/filepath`: 파일 경로 처리
- `strings`: 문자열 조작

### 외부 라이브러리
- **[excelize/v2](https://github.com/xuri/excelize) v2.10.0**: Excel 파일(.xlsx) 생성 및 스타일링
  - Excel 파일 생성
  - 멀티 시트 지원
  - 셀 스타일링 (색상, 폰트, 배경)
  - 의존성:
    - `github.com/richardlehane/mscfb` v1.0.4
    - `github.com/richardlehane/msoleps` v1.0.4
    - `github.com/tiendc/go-deepcopy` v1.7.1
    - `github.com/xuri/efp` v0.0.1
    - `github.com/xuri/nfp` v0.0.2
    - `golang.org/x/crypto` v0.43.0
    - `golang.org/x/net` v0.46.0
    - `golang.org/x/text` v0.30.0

### 빌드 도구
- **Go 모듈 시스템** (go.mod)
- **Makefile**: 크로스 플랫폼 빌드 스크립트
  - `make build`: 현재 OS용 빌드
  - `make build-linux`: Linux용 빌드 (Docker 컨테이너용)
  - `make build-darwin`: macOS용 빌드
  - `make build-all`: 모든 플랫폼용 빌드

## 라이센스

이 프로젝트는 Trivy 오픈소스 프로젝트와 함께 사용하기 위해 작성되었습니다.
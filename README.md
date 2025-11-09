# Trivy Result Parser

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

## 🏗️ 프로젝트 구조

```
parser/
├── main.go              # 진입점 (52 lines)
├── processor/           # 비즈니스 로직
│   ├── types.go        # 데이터 구조체 정의
│   ├── filter.go       # 필터링 로직
│   └── grouper.go      # 그룹화 로직
├── io/                  # 파일 입출력
│   └── file.go         # JSON 읽기/쓰기
├── cli/                 # 커맨드라인 인터페이스
│   └── flags.go        # 플래그 정의 및 검증
└── README.md
```

## 🚀 빌드

```bash
cd parser
go build -o parser
```

## 💻 사용법

### 기본 필터링 (Code 필드 제거)

```bash
./parser -input result-raw.json -output result-filtered.json
```

### 필터링 + 가독성 좋은 JSON 출력

```bash
./parser -input result-raw.json -output result-filtered.json -pretty
```

### 그룹화 모드 (정책별 통합)

```bash
./parser -input result-raw.json -output result-grouped.json -group-by-policy -pretty
```

## 📝 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-input` | (필수) | 입력 JSON 파일 경로 |
| `-output` | (필수) | 출력 JSON 파일 경로 |
| `-remove-code` | `true` | Code 필드 제거 여부 |
| `-group-by-policy` | `false` | 정책별로 그룹화하여 중복 제거 |
| `-pretty` | `false` | JSON 포맷팅 (들여쓰기) |

## 📊 성능

실제 Trivy 스캔 결과 (157KB, 43개 misconfiguration)를 기준으로:

| 모드 | 출력 크기 | 감소율 | Misconfiguration 수 |
|------|-----------|--------|---------------------|
| 원본 | 157 KB | - | 43개 (중복 포함) |
| 필터링 | 38 KB | 75.8% ↓ | 43개 (유지) |
| 그룹화 | 19 KB | 87.9% ↓ | 11개 (정책별 통합) |

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

## 🔧 Trivy와 통합 사용

```bash
# 1. Trivy로 스캔
./trivy config --format json --output raw-result.json terraform-source/

# 2. Parser로 최적화
./parser/parser -input raw-result.json -output filtered-result.json -pretty

# 또는 그룹화 모드로
./parser/parser -input raw-result.json -output grouped-result.json -group-by-policy -pretty
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

## 📄 라이센스

이 프로젝트는 Trivy 오픈소스 프로젝트와 함께 사용하기 위해 작성되었습니다.

## 📞 문의

문제가 발생하거나 개선 사항이 있으면 이슈를 등록해주세요.

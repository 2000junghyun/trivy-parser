# Trivy Parser

## Overview

Trivy Parser is a **Go-based post-processor** for Trivy `--format json` outputs.
It turns large raw scan results into formats that are easier to review and share.

It supports two modes:

- **Preprocess mode**: groups findings by policy ID, splits results per Terraform target (`.tf`), and separates **built-in** vs **custom** policies
- **Excel export mode**: exports findings into an `.xlsx` file (two sheets: `Custom`, `Built-in`) for filtering/sorting/reporting

## Tech Stack

- **Language**: Go (see `go.mod`)
- **Libraries**: `github.com/xuri/excelize/v2` for Excel generation
- **Environment**: single binary, cross-platform (Linux/macOS/Windows)

## Directory Structure

```
.
├── cli/
│   └── flags.go              # CLI flag parsing
│
├── io/
│   ├── file.go               # JSON read/write
│   └── excel.go              # Excel file output (I/O only)
│
├── processor/
│   ├── types.go              # Core Trivy / grouped result structs
│   ├── preprocessor.go       # Group + split logic for preprocess mode
│   └── excel.go              # TrivyResult -> ExcelData transformation
│
├── test-input/
│   └── result-01.json         # Sample Trivy JSON
│
├── test-output/
│   ├── excel/                 # Example Excel outputs
│   └── preprocess/            # Example preprocess outputs
│
├── main.go                    # Entry point
├── Makefile                   # Build helpers
└── go.mod
```

## How It Works

### 1. Preprocess Mode (`processor/preprocessor.go`)

Preprocess mode runs in three stages:

1) **Group by policy ID**
- For each Trivy `Result`, misconfigurations are grouped by `ID`.
- Each grouped policy contains a `Violations` array (resource/line/message), reducing duplicated policy metadata.

2) **Split by target (`.tf`)**
- Only `Target` values that end with `.tf` are processed.
- Results are split into separate files per target.

3) **Separate built-in vs custom**
- Built-in policy: `Namespace` starts with `builtin.`
- Custom policy: anything else (for example `user.*`)

Output filenames are prefixed to indicate policy type:

- `builtin-...json`
- `custom-...json`

The filename is derived from the Trivy target:

- removes the extension (e.g., `main.tf` -> `main`)
- replaces path separators with `%` (e.g., `modules/vpc/main.tf` -> `modules%vpc%main`)

Example outputs:

- `builtin-main.json`
- `custom-main.json`
- `builtin-modules%vpc%main.json`

### 2. Excel Export Mode (`processor/excel.go` + `io/excel.go`)

Excel mode also has a clean split of responsibilities:

- **Transformation (`processor/excel.go`)**: converts `TrivyResult` into flat `ExcelData` rows and separates built-in/custom
- **Output (`io/excel.go`)**: writes an `.xlsx` file with two sheets:
  - `Custom`
  - `Built-in`

The Excel output includes these columns:

- Target, Title, Resource, Severity, Resolution, StartLine, EndLine, PrimaryURL

Styling:

- header row: bold + yellow background
- severity cell: red text for `CRITICAL` and `HIGH`

## How to Run Locally

### 1. Build

```bash
go build -o trivy-parser
```

Or via Makefile:

```bash
make build
```

### 2. Preprocess mode

```bash
./trivy-parser \
  -input ./test-input/result-01.json \
  -output ./test-output/preprocess/ \
  -preprocess \
  -pretty
```

### 3. Excel export mode

```bash
./trivy-parser \
  -input ./test-input/result-01.json \
  -output ./test-output/excel/result.xlsx \
  -excel
```

Note: the output directory must exist for Excel mode.

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | (required) | Path to Trivy JSON result file |
| `-output` | (required) | Output `.xlsx` path (Excel mode) or output directory (Preprocess mode) |
| `-excel` | `false` | Export to `.xlsx` with `Custom` / `Built-in` sheets |
| `-preprocess` | `false` | Group findings and split per `.tf` target |
| `-pretty` | `false` | Pretty-print JSON output in preprocess mode |

Either `-excel` or `-preprocess` must be specified.

## Features / Main Logic

- **Policy grouping**: reduces redundancy by merging duplicate policy metadata
- **Target-based splitting**: produces file-by-file remediation views for Terraform
- **Built-in vs custom separation**: clear visibility into Trivy built-ins vs org-specific policies
- **Severity summary**: preprocess outputs include per-file counts (CRITICAL/HIGH/MEDIUM/LOW)
- **Excel reporting**: two-sheet spreadsheet export with minimal, useful fields

## Motivation / Impact

- **Faster reviews**: Excel output helps non-developers filter/sort findings quickly
- **Better ownership**: preprocess mode enables assigning issues per Terraform file
- **Smaller artifacts**: grouped JSON reduces storage and bandwidth for CI/CD artifacts
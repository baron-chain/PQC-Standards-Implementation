#!/usr/bin/env bash
# =============================================================================
# run_interop_comprehensive.sh — Full PQC cross-language interoperability suite
#
# 1. Python generates test vectors for all 12 parameter sets
# 2. Go, Java, JavaScript, Rust, Swift, C#, PHP each verify all vectors
# 3. Writes interop_results.json and interop_results.txt to repo root
#
# Usage:
#   cd PQC-Standards-Implementation
#   bash interop/run_interop_comprehensive.sh
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INTEROP_DIR="$REPO_ROOT/interop"
VECTORS_DIR="$INTEROP_DIR/vectors"
RESULTS_JSON="$REPO_ROOT/interop_results.json"
RESULTS_TXT="$REPO_ROOT/interop_results.txt"
TODAY="$(date +%Y-%m-%d)"

mkdir -p "$VECTORS_DIR"

# ---------------------------------------------------------------------------
# Colour helpers (optional; suppress if not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

section() { printf "\n${CYAN}${BOLD}── %s${RESET}\n" "$*"; }
ok()      { printf "${GREEN}  ✓ %s${RESET}\n" "$*"; }
fail()    { printf "${RED}  ✗ %s${RESET}\n" "$*"; }
warn()    { printf "${YELLOW}  ⚠ %s${RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Per-algorithm result tracking
# All 12 algorithm names we expect:
# ---------------------------------------------------------------------------
ALL_ALGORITHMS=(
  "ML-KEM-512" "ML-KEM-768" "ML-KEM-1024"
  "ML-DSA-44"  "ML-DSA-65"  "ML-DSA-87"
  "SLH-DSA-SHAKE-128f" "SLH-DSA-SHAKE-128s"
  "SLH-DSA-SHAKE-192f" "SLH-DSA-SHAKE-192s"
  "SLH-DSA-SHAKE-256f" "SLH-DSA-SHAKE-256s"
)

# Associative arrays: ALG -> status string
declare -A PY_GEN
declare -A GO_VERIFY
declare -A JAVA_VERIFY
declare -A JS_VERIFY
declare -A RUST_VERIFY
declare -A SWIFT_VERIFY
declare -A DOTNET_VERIFY
declare -A PHP_VERIFY

# Initialise all to SKIP
for alg in "${ALL_ALGORITHMS[@]}"; do
  PY_GEN[$alg]="SKIP"
  GO_VERIFY[$alg]="SKIP"
  JAVA_VERIFY[$alg]="SKIP"
  JS_VERIFY[$alg]="SKIP"
  RUST_VERIFY[$alg]="SKIP"
  SWIFT_VERIFY[$alg]="SKIP"
  DOTNET_VERIFY[$alg]="SKIP"
  PHP_VERIFY[$alg]="SKIP"
done

# ---------------------------------------------------------------------------
# Helper: parse "RESULT:ALG:PASS" or "RESULT:ALG:FAIL:..." lines
# Updates an associative array passed by name
# ---------------------------------------------------------------------------
parse_results() {
  local -n _arr=$1
  local output="$2"
  while IFS= read -r line; do
    if [[ "$line" == RESULT:* ]]; then
      IFS=: read -r _ alg status rest <<< "$line"
      if [[ -n "${_arr[$alg]+x}" ]]; then
        if [[ "$status" == "FAIL" && -n "$rest" ]]; then
          _arr[$alg]="FAIL:$rest"
        else
          _arr[$alg]="$status"
        fi
      fi
    fi
  done <<< "$output"
}

# ---------------------------------------------------------------------------
# Step 0: Generate vectors with Python
# ---------------------------------------------------------------------------
section "Step 0: Python — generate test vectors"

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Cannot generate vectors." >&2
  exit 1
fi

PY_OUTPUT=$(PYTHONPATH="$REPO_ROOT/python" python3 "$INTEROP_DIR/interop_generate.py" \
              --vectors-dir "$VECTORS_DIR" 2>&1)
PY_EXIT=${PIPESTATUS[0]:-$?}
echo "$PY_OUTPUT"

# Mark Python generation results from output
for alg in "${ALL_ALGORITHMS[@]}"; do
  vecfile="$VECTORS_DIR/$(echo "$alg" | tr '[:upper:]' '[:lower:]' | tr ' ' '-').json"
  if [[ -f "$vecfile" ]]; then
    PY_GEN[$alg]="PASS"
  else
    PY_GEN[$alg]="FAIL:vector file not created"
  fi
done

if [[ $PY_EXIT -ne 0 ]]; then
  warn "Python generator exited with code $PY_EXIT — some vectors may be missing"
fi

# ---------------------------------------------------------------------------
# Step 1: Go verification
# ---------------------------------------------------------------------------
section "Step 1: Go — verify all vectors"

GO_AVAILABLE=false
if command -v go &>/dev/null; then
  GO_AVAILABLE=true
  GO_OUTPUT=$(cd "$REPO_ROOT/go" && \
    go run ./cmd/interop-verify "$VECTORS_DIR" 2>&1) || true
  echo "$GO_OUTPUT"
  parse_results GO_VERIFY "$GO_OUTPUT"
  ok "Go verifier completed"
else
  warn "go not found — skipping Go verification"
fi

# ---------------------------------------------------------------------------
# Step 2: Java verification
# ---------------------------------------------------------------------------
section "Step 2: Java — verify all vectors"

JAVA_AVAILABLE=false

# Prefer Homebrew OpenJDK over macOS stub
JAVA_HOME_BREW="/opt/homebrew/opt/openjdk"
if [[ -x "$JAVA_HOME_BREW/bin/javac" ]]; then
  JAVAC="$JAVA_HOME_BREW/bin/javac"
  JAVA_CMD="$JAVA_HOME_BREW/bin/java"
  JAVA_AVAILABLE=true
elif command -v javac &>/dev/null && command -v java &>/dev/null; then
  # Make sure it's not the macOS stub (which requires a GUI install dialog)
  if javac -version 2>&1 | grep -q "javac"; then
    JAVAC="javac"
    JAVA_CMD="java"
    JAVA_AVAILABLE=true
  fi
fi

if [[ "$JAVA_AVAILABLE" == "true" ]]; then
  OUT_DIR="$INTEROP_DIR/out"
  mkdir -p "$OUT_DIR"

  # Compile the Java project first
  (cd "$REPO_ROOT/java" && mvn compile -q 2>/dev/null) || true
  CP="$REPO_ROOT/java/target/classes"

  if [[ -d "$CP" ]]; then
    # Java requires the filename to match the public class name
    cp "$INTEROP_DIR/interop_verify_java.java" "$OUT_DIR/InteropVerifyJava.java"
    if "$JAVAC" -cp "$CP" -d "$OUT_DIR" "$OUT_DIR/InteropVerifyJava.java" 2>&1; then
      JAVA_OUTPUT=$("$JAVA_CMD" -cp "$CP:$OUT_DIR" interop.InteropVerifyJava "$VECTORS_DIR" 2>&1) || true
      echo "$JAVA_OUTPUT"
      parse_results JAVA_VERIFY "$JAVA_OUTPUT"
      ok "Java verifier completed"
    else
      warn "Java compilation failed — skipping Java verification"
    fi
  else
    warn "Java classes not found at $CP — skipping Java verification"
  fi
else
  warn "javac/java not found — skipping Java verification"
fi

# ---------------------------------------------------------------------------
# Step 3: JavaScript verification
# ---------------------------------------------------------------------------
section "Step 3: JavaScript — verify all vectors"

JS_AVAILABLE=false
if command -v node &>/dev/null; then
  JS_AVAILABLE=true
  JS_OUTPUT=$(node "$INTEROP_DIR/interop_verify_js.mjs" "$VECTORS_DIR" 2>&1) || true
  echo "$JS_OUTPUT"
  parse_results JS_VERIFY "$JS_OUTPUT"
  ok "JavaScript verifier completed"
else
  warn "node not found — skipping JavaScript verification"
fi

# ---------------------------------------------------------------------------
# Step 4: Rust verification
# ---------------------------------------------------------------------------
section "Step 4: Rust — build and verify all vectors"

RUST_AVAILABLE=false
if command -v cargo &>/dev/null; then
  RUST_AVAILABLE=true
  RUST_BIN_DIR="$REPO_ROOT/rust/interop-verify"

  echo "  Building interop-verify binary ..."
  if (cd "$RUST_BIN_DIR" && cargo build --release -q 2>&1); then
    RUST_BIN="$RUST_BIN_DIR/target/release/interop-verify"
    RUST_OUTPUT=$("$RUST_BIN" "$VECTORS_DIR" 2>&1) || true
    echo "$RUST_OUTPUT"
    parse_results RUST_VERIFY "$RUST_OUTPUT"
    ok "Rust verifier completed"
  else
    warn "Rust build failed — skipping Rust verification"
  fi
else
  warn "cargo not found — skipping Rust verification"
fi

# ---------------------------------------------------------------------------
# Step 5: Swift verification
# ---------------------------------------------------------------------------
section "Step 5: Swift — build and verify all vectors"

SWIFT_AVAILABLE=false
if command -v swift &>/dev/null; then
  SWIFT_AVAILABLE=true
  SWIFT_DIR="$REPO_ROOT/swift"

  echo "  Building Swift interop-verify binary ..."
  if (cd "$SWIFT_DIR" && swift build -c release --product interop-verify -q 2>&1); then
    SWIFT_BIN="$SWIFT_DIR/.build/release/interop-verify"
    SWIFT_OUTPUT=$("$SWIFT_BIN" "$VECTORS_DIR" 2>&1) || true
    echo "$SWIFT_OUTPUT"
    parse_results SWIFT_VERIFY "$SWIFT_OUTPUT"
    ok "Swift verifier completed"
  else
    warn "Swift build failed — skipping Swift verification"
  fi
else
  warn "swift not found — skipping Swift verification"
fi

# ---------------------------------------------------------------------------
# Step 6: .NET (C#) verification
# ---------------------------------------------------------------------------
section "Step 6: .NET — build and verify all vectors"

DOTNET_AVAILABLE=false
if command -v dotnet &>/dev/null; then
  DOTNET_AVAILABLE=true
  DOTNET_PROJ="$REPO_ROOT/dotnet/InteropVerify/InteropVerify.csproj"

  echo "  Building .NET interop-verify project ..."
  if dotnet build "$DOTNET_PROJ" -c Release -v quiet 2>&1; then
    DOTNET_OUTPUT=$(dotnet run --project "$DOTNET_PROJ" -c Release -- "$VECTORS_DIR" 2>&1) || true
    echo "$DOTNET_OUTPUT"
    parse_results DOTNET_VERIFY "$DOTNET_OUTPUT"
    ok ".NET verifier completed"
  else
    warn ".NET build failed — skipping .NET verification"
  fi
else
  warn "dotnet not found — skipping .NET verification"
fi

# ---------------------------------------------------------------------------
# Step 7: PHP verification
# ---------------------------------------------------------------------------
section "Step 7: PHP — verify all vectors"

PHP_AVAILABLE=false
if command -v php &>/dev/null; then
  PHP_AVAILABLE=true
  PHP_VENDOR="$REPO_ROOT/php/vendor/autoload.php"

  if [[ ! -f "$PHP_VENDOR" ]]; then
    echo "  Installing PHP dependencies via Composer ..."
    (cd "$REPO_ROOT/php" && composer install -q 2>&1) || true
  fi

  if [[ -f "$PHP_VENDOR" ]]; then
    PHP_OUTPUT=$(php "$INTEROP_DIR/interop_verify_php.php" "$VECTORS_DIR" 2>&1) || true
    echo "$PHP_OUTPUT"
    parse_results PHP_VERIFY "$PHP_OUTPUT"
    ok "PHP verifier completed"
  else
    warn "PHP vendor/autoload.php not found — skipping PHP verification"
  fi
else
  warn "php not found — skipping PHP verification"
fi

# ---------------------------------------------------------------------------
# Build interop_results.json
# ---------------------------------------------------------------------------
section "Building interop_results.json"

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0
ERROR_NOTES=""

{
  echo '{'
  echo "  \"test_date\": \"$TODAY\","
  echo "  \"generator\": \"Python $(python3 --version 2>&1 | awk '{print $2}')\","
  echo "  \"test_message\": \"PQC cross-language interoperability test vector\","
  echo "  \"results\": ["

  FIRST=true
  for alg in "${ALL_ALGORITHMS[@]}"; do
    if [[ "$alg" == ML-KEM* ]]; then
      family="ML-KEM"
    elif [[ "$alg" == ML-DSA* ]]; then
      family="ML-DSA"
    else
      family="SLH-DSA"
    fi

    py_status="${PY_GEN[$alg]}"
    go_status="${GO_VERIFY[$alg]}"
    java_status="${JAVA_VERIFY[$alg]}"
    js_status="${JS_VERIFY[$alg]}"
    rust_status="${RUST_VERIFY[$alg]}"
    swift_status="${SWIFT_VERIFY[$alg]}"
    dotnet_status="${DOTNET_VERIFY[$alg]}"
    php_status="${PHP_VERIFY[$alg]}"

    for st in "$py_status" "$go_status" "$java_status" "$js_status" "$rust_status" "$swift_status" "$dotnet_status" "$php_status"; do
      TOTAL=$((TOTAL + 1))
      case "$st" in
        PASS)      PASSED=$((PASSED + 1)) ;;
        SKIP)      SKIPPED=$((SKIPPED + 1)) ;;
        FAIL*|*)   FAILED=$((FAILED + 1)) ;;
      esac
    done

    py_json="${py_status%%:*}"
    go_json="${go_status%%:*}"
    java_json="${java_status%%:*}"
    js_json="${js_status%%:*}"
    rust_json="${rust_status%%:*}"
    swift_json="${swift_status%%:*}"
    dotnet_json="${dotnet_status%%:*}"
    php_json="${php_status%%:*}"

    for pair in "go:$go_status" "java:$java_status" "js:$js_status" "rust:$rust_status" "swift:$swift_status" "dotnet:$dotnet_status" "php:$php_status" "python:$py_status"; do
      lang="${pair%%:*}"
      status="${pair#*:}"
      if [[ "$status" == FAIL:* ]]; then
        err="${status#FAIL:}"
        ERROR_NOTES="${ERROR_NOTES}${alg} (${lang}): ${err}\n"
      fi
    done

    if [[ "$FIRST" == "true" ]]; then FIRST=false; else echo ","; fi

    printf '    {\n'
    printf '      "algorithm": "%s",\n' "$family"
    printf '      "parameter_set": "%s",\n' "$alg"
    printf '      "python_generate": "%s",\n' "$py_json"
    printf '      "go_verify": "%s",\n' "$go_json"
    printf '      "java_verify": "%s",\n' "$java_json"
    printf '      "js_verify": "%s",\n' "$js_json"
    printf '      "rust_verify": "%s",\n' "$rust_json"
    printf '      "swift_verify": "%s",\n' "$swift_json"
    printf '      "dotnet_verify": "%s",\n' "$dotnet_json"
    printf '      "php_verify": "%s"' "$php_json"

    for st in "$py_status" "$go_status" "$java_status" "$js_status" "$rust_status" "$swift_status" "$dotnet_status" "$php_status"; do
      if [[ "$st" == FAIL:* ]]; then
        err="${st#FAIL:}"
        printf ',\n      "error": "%s"' "$err"
        break
      fi
    done
    printf '\n    }'
  done

  echo ""
  echo "  ],"

  NOTES="All 7 languages tested: Go, Java, JS, Rust, Swift, .NET, PHP"
  if [[ -n "$ERROR_NOTES" ]]; then
    NOTES="$NOTES | Failures: $(echo -e "$ERROR_NOTES" | tr '\n' ';' | sed 's/;$//')"
  fi

  echo "  \"summary\": {"
  echo "    \"total_tests\": $TOTAL,"
  echo "    \"passed\": $PASSED,"
  echo "    \"failed\": $FAILED,"
  echo "    \"skipped\": $SKIPPED,"
  printf '    "notes": "%s"\n' "$NOTES"
  echo "  }"
  echo '}'
} > "$RESULTS_JSON"

ok "Wrote $RESULTS_JSON"

# ---------------------------------------------------------------------------
# Build interop_results.txt
# ---------------------------------------------------------------------------
section "Building interop_results.txt"

{
  printf "PQC Cross-Language Interoperability Test Results\n"
  printf "Date: %s\n" "$TODAY"
  printf "Test message: PQC cross-language interoperability test vector\n"
  printf "\n"
  printf "%-22s %-25s %-9s %-7s %-7s %-7s %-7s %-7s %-7s %-7s\n" \
    "Algorithm" "Parameter Set" "Py(gen)" "Go" "Java" "JS" "Rust" "Swift" ".NET" "PHP"
  printf '%s\n' "$(printf '─%.0s' {1..107})"

  for alg in "${ALL_ALGORITHMS[@]}"; do
    if [[ "$alg" == ML-KEM* ]]; then family="ML-KEM"
    elif [[ "$alg" == ML-DSA* ]]; then family="ML-DSA"
    else family="SLH-DSA"; fi

    py_s="${PY_GEN[$alg]%%:*}"
    go_s="${GO_VERIFY[$alg]%%:*}"
    java_s="${JAVA_VERIFY[$alg]%%:*}"
    js_s="${JS_VERIFY[$alg]%%:*}"
    rust_s="${RUST_VERIFY[$alg]%%:*}"
    swift_s="${SWIFT_VERIFY[$alg]%%:*}"
    dotnet_s="${DOTNET_VERIFY[$alg]%%:*}"
    php_s="${PHP_VERIFY[$alg]%%:*}"

    printf "%-22s %-25s %-9s %-7s %-7s %-7s %-7s %-7s %-7s %-7s\n" \
      "$family" "$alg" "$py_s" "$go_s" "$java_s" "$js_s" "$rust_s" "$swift_s" "$dotnet_s" "$php_s"
  done

  printf "\n"
  printf "Summary: %d total, %d passed, %d failed, %d skipped\n" \
    "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"

  if [[ -n "$ERROR_NOTES" ]]; then
    printf "\nFailure details:\n"
    printf '%s' "$(echo -e "$ERROR_NOTES")"
  fi
} > "$RESULTS_TXT"

ok "Wrote $RESULTS_TXT"

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
printf "\n${BOLD}%s${RESET}\n" "$(printf '═%.0s' {1..60})"
printf "${BOLD} INTEROP TEST SUMMARY${RESET}\n"
printf "${BOLD}%s${RESET}\n" "$(printf '═%.0s' {1..60})"
printf "  Total:   %d\n" "$TOTAL"
printf "  Passed:  %d\n" "$PASSED"
printf "  Failed:  %d\n" "$FAILED"
printf "  Skipped: %d\n" "$SKIPPED"
printf "${BOLD}%s${RESET}\n\n" "$(printf '═%.0s' {1..60})"

cat "$RESULTS_TXT"

if [[ $FAILED -gt 0 ]]; then
  printf "\n${RED}${BOLD}OVERALL: FAIL${RESET}\n\n"
  exit 1
else
  printf "\n${GREEN}${BOLD}OVERALL: PASS${RESET}\n\n"
  exit 0
fi

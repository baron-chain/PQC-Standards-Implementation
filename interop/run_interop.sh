#!/usr/bin/env bash
# =============================================================================
# run_interop.sh -- Cross-language ML-DSA-65 interoperability test runner
#
# Generates test vectors with the Python implementation, then verifies the
# signature in every available language.  Reports per-language PASS/FAIL and
# an overall summary.
#
# Usage:
#     cd PQC-Standards-Implementation
#     bash interop/run_interop.sh
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INTEROP_DIR="$REPO_ROOT/interop"
VECTORS="$INTEROP_DIR/mldsa65_vectors.json"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

run_step() {
    local lang="$1"
    shift
    printf "\n────────────────────────────────────────\n"
    printf " %s\n" "$lang"
    printf "────────────────────────────────────────\n"
    if "$@"; then
        RESULTS+=("PASS  $lang")
        ((PASS++))
    else
        RESULTS+=("FAIL  $lang")
        ((FAIL++))
    fi
}

skip_step() {
    local lang="$1"
    local reason="$2"
    printf "\n────────────────────────────────────────\n"
    printf " %s -- SKIPPED (%s)\n" "$lang" "$reason"
    printf "────────────────────────────────────────\n"
    RESULTS+=("SKIP  $lang ($reason)")
    ((SKIP++))
}

# ---------------------------------------------------------------------------
# Step 0: Generate vectors with Python
# ---------------------------------------------------------------------------

printf "============================================\n"
printf " ML-DSA-65 Cross-Language Interop Tests\n"
printf "============================================\n"

echo ""
echo "[*] Generating test vectors with Python ..."

if command -v python3 &>/dev/null; then
    PYTHONPATH="$REPO_ROOT/python" python3 "$INTEROP_DIR/generate_vectors.py"
else
    echo "ERROR: python3 not found -- cannot generate vectors."
    exit 1
fi

if [ ! -f "$VECTORS" ]; then
    echo "ERROR: vectors file was not created."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Verify with Python (sanity check)
# ---------------------------------------------------------------------------

if command -v python3 &>/dev/null; then
    run_step "Python" env PYTHONPATH="$REPO_ROOT/python" python3 "$INTEROP_DIR/verify_python.py"
else
    skip_step "Python" "python3 not found"
fi

# ---------------------------------------------------------------------------
# Step 2: Verify with Go
# ---------------------------------------------------------------------------

if command -v go &>/dev/null; then
    run_step "Go" bash -c "cd '$REPO_ROOT/go' && go run '../interop/verify_go.go'"
else
    skip_step "Go" "go not found"
fi

# ---------------------------------------------------------------------------
# Step 3: Verify with JavaScript (Node.js)
# ---------------------------------------------------------------------------

if command -v node &>/dev/null; then
    run_step "JavaScript" node "$INTEROP_DIR/verify_js.mjs"
else
    skip_step "JavaScript" "node not found"
fi

# ---------------------------------------------------------------------------
# Step 4: Verify with Java
# ---------------------------------------------------------------------------

if command -v javac &>/dev/null && command -v java &>/dev/null; then
    run_step "Java" bash -c "
        cd '$REPO_ROOT'
        # Compile the project if needed
        if [ -f java/pom.xml ]; then
            (cd java && mvn compile -q 2>/dev/null) || true
        fi
        # Compile the verification script
        mkdir -p interop/out
        javac -cp java/target/classes -d interop/out interop/verify_java.java
        # Run it
        java -cp java/target/classes:interop/out interop.VerifyJava
    "
else
    skip_step "Java" "javac/java not found"
fi

# ---------------------------------------------------------------------------
# Step 5: Verify with Rust
# ---------------------------------------------------------------------------

if command -v cargo &>/dev/null; then
    run_step "Rust" bash -c "
        cd '$REPO_ROOT'
        # Copy the test file into the Rust crate's test directory
        cp interop/verify_rust.rs rust/ml-dsa/tests/interop_test.rs
        cd rust
        cargo test --package ml-dsa --test interop_test -- --nocapture 2>&1
        STATUS=\$?
        # Clean up the copied test file
        rm -f ml-dsa/tests/interop_test.rs
        exit \$STATUS
    "
else
    skip_step "Rust" "cargo not found"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf "\n"
printf "============================================\n"
printf " SUMMARY\n"
printf "============================================\n"
for r in "${RESULTS[@]}"; do
    printf "  %s\n" "$r"
done
printf "\n"
printf "  Passed: %d   Failed: %d   Skipped: %d\n" "$PASS" "$FAIL" "$SKIP"
printf "============================================\n"

if [ "$FAIL" -gt 0 ]; then
    printf "\nOVERALL: FAIL\n"
    exit 1
else
    printf "\nOVERALL: PASS\n"
    exit 0
fi

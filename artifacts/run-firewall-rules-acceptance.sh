#!/usr/bin/env bash
# Fast, dependency-free acceptance for device-group firewall rule priority,
# conflict detection and explicit dispatch rejection.
#
# Compiles the REAL std-only gateway core
# (`rust/gateway/src/firewall_rules.rs`) with a plain rustc:
#   1. runs its inline unit tests (`rustc --test`),
#   2. builds and runs the three-group-configuration acceptance harness,
#   3. writes `artifacts/firewall-rules-acceptance.json`.
#
# Exits non-zero if any effective-rule expectation fails or a conflicting
# configuration is not rejected.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UID_HINT="${FEEDBACK_JOB_UID:-38808}"

CORE_REL="rust/gateway/src/firewall_rules.rs"
RUNNER_REL="artifacts/firewall_rules_acceptance.rs"

# Allow a verifier copy of this script to still locate the checkout.
if [[ ! -f "${ROOT}/${CORE_REL}" ]]; then
  for candidate in "/home/dev/feedback/uid${UID_HINT}" "${PWD}"; do
    if [[ -f "${candidate}/${CORE_REL}" ]]; then
      ROOT="${candidate}"
      break
    fi
  done
fi

if [[ ! -f "${ROOT}/${CORE_REL}" || ! -f "${ROOT}/${RUNNER_REL}" ]]; then
  echo "error: cannot locate Firezone checkout containing ${CORE_REL}" >&2
  exit 3
fi

find_rustc() {
  if [[ -n "${RUSTC:-}" && -x "${RUSTC}" ]]; then
    echo "${RUSTC}"
    return 0
  fi
  if command -v rustc >/dev/null 2>&1 && rustc --version >/dev/null 2>&1; then
    command -v rustc
    return 0
  fi
  local candidate newest=""
  for candidate in \
    /home/dev/.rustup/toolchains/*/bin/rustc \
    "${HOME}/.rustup/toolchains/"*/bin/rustc \
    /home/dev/toolchains/rustup/toolchains/*/bin/rustc; do
    [[ -x "${candidate}" ]] || continue
    # Prefer a stable toolchain, otherwise take the lexically highest version.
    if [[ "${candidate}" == *stable* ]]; then
      echo "${candidate}"
      return 0
    fi
    if [[ -z "${newest}" || "${candidate}" > "${newest}" ]]; then
      newest="${candidate}"
    fi
  done
  if [[ -n "${newest}" ]]; then
    echo "${newest}"
    return 0
  fi
  return 1
}

RUSTC_BIN="$(find_rustc)" || {
  echo "error: rustc is required for the zero-dependency acceptance (Rust toolchain not found)." >&2
  exit 3
}

WORK="$(mktemp -d -t firewall-rules-acceptance-XXXXXX)"
trap 'rm -rf "${WORK}"' EXIT

echo "Using rustc: $("${RUSTC_BIN}" --version)"
echo "Repository:  ${ROOT}"
echo

echo "==> [1/2] core unit tests (${CORE_REL})"
"${RUSTC_BIN}" --edition=2021 -D warnings --test \
  "${ROOT}/${CORE_REL}" -o "${WORK}/core_tests"
"${WORK}/core_tests"

echo
echo "==> [2/2] three group configurations + conflict rejection"
"${RUSTC_BIN}" --edition=2021 \
  "${ROOT}/${RUNNER_REL}" -o "${WORK}/acceptance"

REPORT="${ROOT}/artifacts/firewall-rules-acceptance.json"
mkdir -p "$(dirname "${REPORT}")"
"${WORK}/acceptance" "${REPORT}"

echo
echo "Evidence: ${REPORT}"

# Optional Elixir control-plane parity check. Runs when a working `elixir`
# is available (PATH, ELIXIR_BIN, or the local user-space bootstrap); otherwise
# it is skipped because the Rust acceptance already covers the contract.
ELIXIR_BIN_RESOLVED=""
if [[ -n "${ELIXIR_BIN:-}" && -x "${ELIXIR_BIN}" ]]; then
  ELIXIR_BIN_RESOLVED="${ELIXIR_BIN}"
elif command -v elixir >/dev/null 2>&1 && elixir --version >/dev/null 2>&1; then
  ELIXIR_BIN_RESOLVED="$(command -v elixir)"
elif [[ -x /home/dev/tmp/elixir-bootstrap/root/usr/bin/elixir ]]; then
  export PATH="/home/dev/tmp/elixir-bootstrap/wrap:/home/dev/tmp/elixir-bootstrap/root/usr/bin:${PATH}"
  ELIXIR_BIN_RESOLVED="/home/dev/tmp/elixir-bootstrap/root/usr/bin/elixir"
fi

if [[ -n "${ELIXIR_BIN_RESOLVED}" ]]; then
  echo
  echo "==> [extra] Elixir portal rule engine parity (${ELIXIR_BIN_RESOLVED})"
  (cd "${ROOT}" && "${ELIXIR_BIN_RESOLVED}" artifacts/firewall_rules_acceptance.exs)
else
  echo
  echo "==> [skip] Elixir parity check (no elixir runtime found; Rust acceptance is authoritative)"
fi

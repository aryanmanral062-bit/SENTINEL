# SENTINEL — Security Change Impact Analyzer

> **"A Python-based tool that analyses proposed changes in simulated system configurations, identifies security risks caused by individual changes or interactions between security settings, and recommends corrective actions."**

---

## 1. Project Overview

**SENTINEL** is a command-line security analysis prototype designed to inspect and compare simulated system configurations. In modern software and infrastructure deployments, configuration changes are a frequent source of security regressions. While a single configuration modification might appear safe in isolation, its interaction with other settings can inadvertently compromise system security.

SENTINEL addresses this challenge by evaluating both a baseline (original) and a proposed system configuration against predefined security rules, mapping the transitions across a formal 2×2 change impact matrix, detecting **silent dependency breaks**, and generating actionable remediation guidance in a structured terminal interface.

---

## 2. Problem Statement

System administrators and developers frequently modify system settings (such as firewall states, password length thresholds, or network exposure levels). However:
- Isolated parameter reviews miss **cross-parameter dependencies**. For example, leaving authentication disabled might be acceptable when an API is internal, but switching that API to public without also enabling authentication creates a critical vulnerability.
- Manual reviews often overlook the fact that an **unchanged setting** can become inadequate when its surrounding operational context changes.
- Traditional configuration diff tools only flag which text values changed, without assessing the **security semantics** or **risk impact** of those changes.

---

## 3. Objectives

- **Automated Policy Verification:** Independently evaluate configuration states against strict, predefined security rules.
- **Change Impact Classification:** Categorize every setting transition into one of four distinct states: *No weakness detected*, *New weakness*, *Resolved weakness*, or *Existing weakness*.
- **Silent Dependency Break Detection:** Identify dangerous interactions where changing one parameter invalidates the safety of an unchanged companion parameter.
- **Actionable Remediation:** Provide specific, unambiguous recommendations for any detected vulnerability.
- **Strictly Educational & Safe Execution:** Operate entirely on local, simulated JSON configurations without touching operating system settings or production environments.

---

## 4. Key Features

- **Strict Schema & Type Validation:** Rejects missing keys, illegal types, unrecognized attributes, negative lengths, and invalid values before analysis.
- **Deterministic 2×2 Change Impact Matrix:** Classifies rule outcomes systematically across configuration transitions.
- **Silent Dependency Break Detection:** Explains which setting changed, which unchanged setting was affected, why the dependency became unsafe, and how to fix it.
- **Rich Terminal Reporting:** Uses structured tables, status badges, alert panels, and completion summaries via the `rich` library.
- **Safe & User-Friendly Error Handling:** Intercepts syntax and schema errors cleanly without exposing raw Python tracebacks.

---

## 5. Key Differentiating Feature: Silent Dependency Break Detection

The cornerstone capability of SENTINEL is detecting **Silent Dependency Breaks**.

### What is a Silent Dependency Break?

A silent dependency break occurs when:
1. **Setting A changes** (e.g., `api_exposure` transitions from `"internal"` to `"public"`).
2. **Setting B remains unchanged** (e.g., `authentication_required` remains `false`).
3. Under the baseline context (`api_exposure: "internal"`), `authentication_required: false` was permissible.
4. However, under the new context (`api_exposure: "public"`), the unchanged `authentication_required: false` setting becomes inadequate and violates security policy.
5. As a result, a vulnerability is introduced **without Setting B ever being touched**.

### How SENTINEL Solves This

SENTINEL evaluates each configuration state independently through `rules.py` and then correlates evaluation shifts with configuration deltas in `compare.py`. When an API dependency fails in the proposed configuration while having passed in the original configuration, SENTINEL inspects whether the exposure changed while authentication remained disabled. If so, it flags a **Silent Dependency Break**, highlighting:
- **Changed Setting:** `api_exposure` (`internal` &rarr; `public`)
- **Affected Unchanged Setting:** `authentication_required` (`false`)
- **Why Dependency Became Unsafe:** Publicly exposing endpoints without authentication allows unrestricted anonymous access.
- **Corrective Action:** Enable authentication (`authentication_required: true`) or revert the API exposure to `internal`.

---

## 6. Architecture & Module Responsibilities

The project follows a clean, modular architecture separating configuration management, rule evaluation, comparison analysis, and CLI presentation:

```
SENTINEL/
│
├── main.py              # CLI entry point, orchestration, and Rich terminal rendering
├── config.py            # JSON loading, schema validation, and error management
├── rules.py             # Predefined security rules evaluated in isolation
├── compare.py           # 2x2 matrix impact comparison & dependency break detection
│
├── original.json        # Baseline simulated configuration sample
├── proposed.json        # Proposed simulated configuration sample (with dependency break)
│
├── requirements.txt     # Python dependencies
├── README.md            # Comprehensive project documentation
│
└── tests/
    ├── __init__.py
    ├── test_config.py   # Unit tests for schema validation and error scenarios
    ├── test_rules.py    # Unit tests for independent rule evaluations
    └── test_compare.py  # Unit and integration tests for impact matrix and sample files
```

### Module Responsibilities

| Module | Core Responsibility |
|---|---|
| `config.py` | Loads JSON files, ensures root is a dictionary, validates the four mandatory settings (`firewall_enabled`, `password_min_length`, `api_exposure`, `authentication_required`), checks types and allowed values, and raises structured `ConfigError` exceptions. |
| `rules.py` | Evaluates configurations against Rule 1 (Firewall Check), Rule 2 (Password Length Check &ge; 8), and Rule 3 (API Authentication Dependency). Evaluates inputs in isolation without comparing changes. |
| `compare.py` | Consumes evaluation results from `rules.py`, categorizes shifts via the 2×2 classification matrix, detects silent dependency breaks, and attaches corrective recommendations. |
| `main.py` | Parses `--original` and `--proposed` CLI arguments with `argparse`, coordinates module calls, traps errors gracefully, and renders terminal outputs using `rich`. |

---

## 7. Technology Stack

- **Language:** Python 3 (Python 3.11+)
- **Configuration Format:** JSON (`json` standard library)
- **Data Structures:** Python typed dictionaries and dataclasses (`typing`, `dataclasses`)
- **CLI Parsing:** `argparse` standard library
- **Path Handling:** `pathlib.Path` standard library
- **Terminal UI:** `rich` library (tables, panels, colored text)
- **Testing:** `unittest` standard library and `pytest`

---

## 8. Installation Instructions

1. **Clone or navigate to the repository:**
   ```bash
   cd c:\Users\acer\OneDrive\Desktop\sentinel
   ```

2. **Verify Python 3 is installed:**
   ```bash
   python --version
   ```

3. **Install required dependencies:**
   ```bash
   python -m pip install -r requirements.txt
   ```

---

## 9. Execution Commands

### Running Analysis with Sample Files
```bash
python main.py --original original.json --proposed proposed.json
```

### Running Analysis with Custom Configuration Files
```bash
python main.py --original /path/to/baseline.json --proposed /path/to/candidate.json
```

### Displaying CLI Help
```bash
python main.py --help
```

### Running the Automated Test Suite
Using `unittest`:
```bash
python -m unittest discover -s tests -v
```

Using `pytest`:
```bash
python -m pytest -v
```

---

## 10. Sample Input Explanation

The prototype includes two sample files demonstrating a realistic silent dependency break:

### `original.json` (Baseline Configuration)
```json
{
    "firewall_enabled": true,
    "password_min_length": 12,
    "api_exposure": "internal",
    "authentication_required": false
}
```
* **Firewall:** Enabled (`true`) &rarr; **PASS**
* **Password Min Length:** 12 (&ge; 8) &rarr; **PASS**
* **API Exposure:** `"internal"` with no authentication &rarr; **PASS** (Permissible for internal networks under Rule 3)

### `proposed.json` (Proposed Configuration)
```json
{
    "firewall_enabled": true,
    "password_min_length": 12,
    "api_exposure": "public",
    "authentication_required": false
}
```
* **Firewall:** Enabled (`true`) &rarr; **PASS**
* **Password Min Length:** 12 (&ge; 8) &rarr; **PASS**
* **API Exposure:** `"public"` with no authentication &rarr; **FAIL** (Violates Rule 3)

---

## 11. Expected Output Explanation

When executing SENTINEL with the sample files, the terminal report is organized into seven sections:

1. **SENTINEL Application Header:** Displays tool name, version, and mission statement.
2. **Configuration Input Status:** Displays a side-by-side comparison table showing original vs. proposed raw settings and delta status (`UNCHANGED` vs. `MODIFIED`).
3. **Security Rule Evaluation:** Summarizes individual rule evaluations for both configurations independently:
   - Firewall Check: **PASS** (Original) / **PASS** (Proposed)
   - Password Length Check: **PASS** (Original) / **PASS** (Proposed)
   - API Authentication Dependency Check: **PASS** (Original) / **FAIL** (Proposed)
4. **Change Impact Analysis:** Categorizes each rule's outcome using the 2×2 matrix:
   - Firewall Check &rarr; *No weakness detected*
   - Password Length Check &rarr; *No weakness detected*
   - API Authentication Dependency Check &rarr; *New weakness*
5. **Dependency Break Detection:** Emits a highlighted critical alert explaining:
   - `api_exposure` was modified from `"internal"` to `"public"`.
   - `authentication_required` remained unchanged as `False`.
   - Unauthenticated public exposure allows unrestricted anonymous external requests.
   - Recommended fix: set `authentication_required: true` or revert exposure to `internal`.
6. **Corrective Recommendations:** Lists specific remediation actions for all detected weaknesses.
7. **Analysis Completion Status & Verdict:**
   - New Weaknesses: **1**
   - Resolved Weaknesses: **0**
   - Existing Weaknesses: **0**
   - No Weakness Detected: **2**
   - Final Verdict: `ANALYSIS VERDICT: REJECT PROPOSED CHANGE`

---

## 12. Limitations & Prototype Boundaries

SENTINEL is deliberately scoped as a rigorous academic and technical prototype:
- **Local CLI Tool Only:** Does not provide web interfaces, GUIs, or cloud dashboards.
- **Simulated Data Only:** Operates exclusively on JSON configuration files. It does **not** inspect or alter real operating system settings, network interfaces, or firewall daemons.
- **Fixed Predefined Rules:** Evaluates exactly three predefined security rules across four settings. It is not an extensible general-purpose compliance auditor.
- **Educational Scope:** Demonstrates core principles of change impact analysis and dependency verification for software architecture and security coursework.

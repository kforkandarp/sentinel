<h1 align="center">🛡️ Sentinel</h1>

<p align="center">
  <b>AI Security Gateway for Agentic Commerce</b><br>
  Preventing untrusted content from independently authorizing consequential actions.
</p>
<p align="center">
  🛡️ Detection ≠ Authorization &nbsp;•&nbsp; 🔒 Deterministic Policy Gate &nbsp;•&nbsp; 🧾 Audit Trail
</p>

---

Autonomous commerce agents evaluate external documents—such as vendor quotes, invoices, and catalog listings—to prepare purchase proposals.

When these external documents are parsed, adversaries can embed prompt injections designed to manipulate the model's reasoning and downstream actions.

Sentinel provides an application-level control plane that isolates probabilistic prompt injection detection from deterministic action authorization.

> **Core Security Invariant:**
>
> $$\text{Detection} \neq \text{Authorization}$$
>
> Untrusted content may influence an agent's reasoning, but it cannot independently grant authorization to execute a consequential action.

---

## 🎯 The Problem

Autonomous agents interact with third-party data sources that cannot be trusted:

* Vendor catalog quotes and product listings
* Invoices and payment requests
* Product specification sheets (PDF, Markdown, TXT)
* Logistics and return notices

These sources can carry **prompt injection**—malicious instructions embedded inside content that attempt to manipulate an AI system's downstream operations.

Relying solely on an ML detector creates a single point of failure: when an adversarial instruction evades detection (a false negative), an unconstrained agent will execute the attacker's payload.

Sentinel addresses this by enforcing a hard, deterministic authorization boundary between agent reasoning and external action execution.

---

## 🛡️ Core Security Principle

Sentinel divides security responsibilities across four distinct layers:

| Layer | Core Question | Architectural Role |
| :--- | :--- | :--- |
| **Detection** | Does this content look suspicious? | Probabilistic threat evidence |
| **Provenance** | Where did this content come from? | Contextual metadata |
| **Policy Gate** | Is the proposed action permitted? | Deterministic authorization boundary |
| **Executor** | Can this action run? | Enforces authorization |

### Key Definitions

* **Prompt injection:** Malicious instructions embedded inside content that attempt to manipulate an AI system's behavior.
* **Untrusted content:** Content originating from external or vendor sources that must not be granted default authority.
* **Benign:** Legitimate, non-malicious content.
* **Adversarial:** Content intentionally structured to manipulate, attack, or bypass system constraints.
* **Provenance:** Metadata describing where content came from and how it entered Sentinel. It provides context; it does not establish safety or authorization.
* **Authorization:** Verification that a proposed action strictly adheres to user-delegated spending and category limits.
* **Policy Gate:** The deterministic component that renders authorization decisions (`ALLOW`, `REVIEW`, `DENY`).
* **Inspection:** Structural and machine learning analysis performed on content before downstream agent processing.

---

## 🏗️ Architecture

![Sentinel Architecture](assets/architecture.png)

The Sentinel control plane processes requests through a sequential pipeline:

1. **Ingestion:** Parses text and documents (`.txt`, `.md`, `.pdf`), generates a SHA-256 artifact hash and records provenance metadata.
2. **Inspection Router:** Directs payloads to `BLOCK`, `CACHE_REUSE`, or `DEEP_INSPECT` to manage inspection overhead. *A status of "not deeply inspected" is never equivalent to "safe" or "authorized."*
3. **Detector:** Analyzes raw text using `protectai/deberta-v3-base-prompt-injection-v2` at a fixed classification threshold of `0.5`. It acts as an advisory threat signal, not an authorization authority.
4. **Agent Action Proposal:** Captures proposed actions (`product_id`, `category`, `quantity`, `unit_price`, `total`, `correlation_id`) without inherent execution power.
5. **Policy Gate:** Evaluates proposals against hard spending rules and user-delegated `TaskScope` constraints (allowed categories and budget ceilings).
6. **Action Executor:** Executes consequential actions only when provided with an explicit `ALLOW` decision from the Policy Gate. `REVIEW` and `DENY` outcomes never execute.
7. **Audit Logging:** Emits structured audit events (`INGESTED`, `INSPECTION_ROUTED`, `DETECTED`, `ACTION_PROPOSED`, `POLICY_DECIDED`, `ACTION_EXECUTED` / `ACTION_BLOCKED`) linked by a single `correlation_id`.

---

## 🔍 Detection vs. Authorization

A `SAFE` detector verdict does not authorize an action:

* **The detector is probabilistic:** It scores the semantic likelihood of an attack. It can produce false positives and false negatives.
* **The Policy Gate is deterministic:** It evaluates hard constraints. Even if the detector misses an attack, the Policy Gate rejects actions that exceed the user's budget or propose unauthorized categories.

---

## 🔐 Authorization Policy

The Policy Gate combines deterministic spending rules with explicit user-delegated `TaskScope` constraints:

| Proposed Purchase Total | Policy Decision | Execution Outcome |
| :--- | :--- | :--- |
| ≤ ₹5,000 and within delegated scope | **ALLOW** | **EXECUTED** |
| ≤ ₹5,000 with security evidence requiring review | **REVIEW** | **BLOCKED** |
| > ₹5,000 and ≤ ₹50,000 | **REVIEW** | **BLOCKED** |
| > ₹50,000 | **DENY** | **BLOCKED** |
| Any amount with unauthorized category | **DENY** | **BLOCKED** |

---

## 🎬 Demonstration

Sentinel provides a single-page Streamlit interface communicating with the FastAPI backend over HTTP.

![Sentinel UI](assets/sentinel_ui.png)

### 1. Safe Purchase (Legitimate Workflow)
* **Artifact:** `data/corpus/benign/bulk_cable_accessory_quote_009.txt`
* **Flow:** Detector classifies the content as safe; the proposal is within user-delegated scope (`cable`) and budget ($\le \text{₹}5,000$).
* **Result:** `ALLOW` $\rightarrow$ **Action Executed**.

![Safe Purchase](assets/safe_purchase.png)

### 2. Suspicious Content (Detected Attack)
* **Artifact:** `data/corpus/adversarial/wholesale_catalog_hidden_instruction_021.txt`
* **Flow:** Detector identifies suspicious command overrides within the document.
* **Result:** `REVIEW` $\rightarrow$ **Action Blocked**.

![Suspicious Content](assets/suspicious_document.png)

### 3. Detector Miss (Defense in Depth)
* **Artifact:** `data/corpus/adversarial/monitor_category_substitution_014.md`
* **Flow:** An adversarial markdown document bypasses the detector (`SAFE`). The proposal requests an unauthorized category (`gift_card`) while the user's delegated `TaskScope` permits only `laptop`.
* **Result:** The Policy Gate independently rejects the action (`DENY`) $\rightarrow$ **Action Blocked**.

![Detector Miss](assets/detector_miss.png)

---

## 📊 Evaluation

Quantitative evaluation is performed against a frozen benchmark of 240 examples at `data/benchmark/dataset.json` (120 `SAFE`, 120 `INJECTION`) evaluated using `protectai/deberta-v3-base-prompt-injection-v2` at threshold `0.5`.

### Overall Benchmark Metrics

| Metric | Measured Value | Confusion Matrix Breakdown |
| :--- | :--- | :--- |
| **Accuracy** | 81.25% | **True Positives (TP):** 86 |
| **Precision** | 88.66% | **True Negatives (TN):** 109 |
| **Recall** | 71.67% | **False Positives (FP):** 11 |
| **F1 Score** | 79.26% | **False Negatives (FN):** 34 |
| **False Positive Rate (FPR)** | 9.17% | Total Examples: 240 |
| **False Negative Rate (FNR)** | 28.33% | Balance: 120 Safe / 120 Injection |

### Inference Latency

| Minimum | Mean | Median | P95 | Maximum |
| :--- | :--- | :--- | :--- | :--- |
| 6.52 ms | 285.67 ms | 289.25 ms | 361.17 ms | 463.48 ms |

### Accuracy by Attack Category

| Category | Accuracy | Correct / Total |
| :--- | :--- | :--- |
| `direct_injection` | 100.0% | 20 / 20 |
| `obfuscation_evasion` | 93.3% | 14 / 15 |
| `benign_security_discussion` | 90.0% | 18 / 20 |
| `semantic_injection` | 90.0% | 18 / 20 |
| `commerce_agent_injection` | 80.0% | 12 / 15 |
| `adversarial_looking_benign` | 76.0% | 19 / 25 |
| `url_web_injection` | 60.0% | 9 / 15 |
| `indirect_content_injection` | 55.0% | 11 / 20 |
| `document_injection` | 13.3% | 2 / 15 |

### Accuracy by Sample Difficulty

| Difficulty Level | Accuracy | Correct / Total |
| :--- | :--- | :--- |
| `EASY` | 100.0% | 59 / 59 |
| `MEDIUM` | 98.86% | 87 / 88 |
| `HARD` | 91.40% | 85 / 93 |

---

## 📚 Commerce Corpus

The repository maintains a separate, realistic commerce corpus at `data/corpus/`:

* **Total Artifacts:** 24 documents
* **Class Distribution:** 12 benign, 12 adversarial
* **File Formats:** TXT, Markdown, and PDF

This corpus is used for end-to-end pipeline verification and integration testing. It is distinct from the frozen 240-example benchmark.

---

## ⚠️ Failure Analysis & Limitations

1. **Document & Indirect Injections:** The detector struggles with embedded document instructions (`document_injection`: 13.3% accuracy; `indirect_content_injection`: 55.0% accuracy). Adversarial directives hidden inside structured formats or tables can evade detection.

2. **False Negatives:** With an overall False Negative Rate of 28.33%, detection alone cannot ensure execution safety.

3. **Scope-Compliant Injections:** If an attacker influences an agent to propose an action that falls completely within the user's pre-authorized category and budget ceiling, the Policy Gate will approve it. Sentinel restricts execution authority; it does not guarantee complete semantic understanding.

4. **In-Process Capability Registry:** The current authorization mechanism uses an in-memory token registry to enforce execution boundaries. Production deployments require distributed capabilities with cryptographic signing and replay protection.

5. **No Persistent Vendor Reputation:** Vendor risk tracking and historical reputation databases are not implemented.

---

## 🧪 Testing

The automated pytest suite covers provenance immutability, router caching, detector inference, spending policies, capability validation, API schemas, and end-to-end integration scenarios.

![Test Suite](assets/test_cases.png)

```powershell
pytest -q
```

Status: **96 passed**

---

## 🔌 API Documentation
FastAPI runs locally on `http://127.0.0.1:8000`. Interactive OpenAPI documentation is available at `/docs`.

### 1. `GET /health`

Returns operational gateway readiness:

```json
{
  "status": "ok",
  "service": "sentinel-gateway",
  "version": "0.1.0"
}
```

### 2. `POST /ingest-file`

Accepts `multipart/form-data` uploads (`.txt`, `.md`, `.pdf`), extracts text via the ingestion layer, and returns untrusted content bound to structural provenance metadata:

```bash
curl -X POST http://127.0.0.1:8000/ingest-file \
  -F "file=@data/corpus/benign/bulk_cable_accessory_quote_009.txt"
```

### 3. `POST /scan`

Executes end-to-end routing, detection, policy authorization, execution gating, and audit logging:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Catalog quote for bulk Cat6 Ethernet cables.",
    "product_id": "cat6_spool_100",
    "category": "cable",
    "quantity": 2,
    "unit_price": 1200.00,
    "task_scope": {
      "allowed_categories": ["cable", "accessory"],
      "max_budget": 5000.00
    }
  }'
```
---

## 📁 Project Structure

```plaintext
Sentinel_v1/
├── assets/                         # Documentation visual assets
├── data/
│   ├── benchmark/
│   │   ├── dataset.json            # Frozen 240-example benchmark
│   │   └── results.json            # Recorded benchmark evaluation metrics
│   └── corpus/                     # 24-artifact commerce evaluation corpus
│       ├── adversarial/
│       ├── benign/
│       └── manifest.json
├── src/
│   └── sentinel/
│       ├── agent/                  # ActionProposal schemas & reasoning models
│       ├── audit/                  # AuditEvent schemas & correlation logger
│       ├── detection/              # Locked DeBERTa-v3 detector implementation
│       ├── evaluation/             # Benchmark metrics calculator & runners
│       ├── execution/              # ActionExecutor & capability gate boundary
│       ├── gateway/                # Ingestion & document extraction
│       ├── inspection/             # Router & provenance-scoped cache
│       ├── policy/                 # PolicyGate & TaskScope rule definitions
│       ├── app.py                  # FastAPI application entry point
│       ├── config.py               # Gateway environment configuration
│       ├── hashing.py              # SHA-256 hashing utility
│       └── provenance.py           # Trusted ProvenanceContext factory
├── tests/                          # 96-test automated pytest suite
├── demo_ui.py                      # Single-page Streamlit presentation client
├── pyproject.toml                  # Packaging specifications & dependencies
└── README.md                       # Project documentation
```

---

## 🚀 Local Setup

### 1. Environment Installation

Requires Python 3.11 or higher.

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Windows PowerShell
# source .venv/bin/activate     # Linux / macOS

# Install package in editable mode
pip install -e .
```

### 2. Run Test Suite

```powershell
pytest -q
```

### 3. Start FastAPI Backend

```powershell
uvicorn sentinel.app:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Start Streamlit Demo UI

In a separate terminal with the virtual environment activated:

```powershell
streamlit run demo_ui.py
```

---

## 🔁 Reproducing the Benchmark

The 240-example benchmark at `data/benchmark/dataset.json` is frozen. To re-run model evaluation and regenerate accuracy, latency, and category metrics:

```powershell
python -m sentinel.evaluation.runner
```

To run the end-to-end scenario verification pipeline across the commerce corpus:

```powershell
python -m sentinel.evaluation.runner_e2e
```

---

## 🔮 Future Work

The current prototype deliberately keeps its authorization and inspection model small and explicit. A production system could extend Sentinel with additional security intelligence without weakening the authorization boundary.

* **Security Telemetry & Vendor History:** Introduce a persistent database for security-relevant telemetry such as vendor history, artifact hashes, inspection outcomes, detection results, policy decisions, and correlated audit events. Over time, this history could support vendor risk profiling, anomaly detection, and more informed inspection decisions.

* **Specialized Document Ingestion Detectors:** Incorporate domain-specific classifiers and document-aware analysis to improve detection of indirect injections embedded in structured tables, PDFs, and other document formats.

* **Adaptive Inspection:** Use accumulated security telemetry and historical vendor behavior to determine when deeper inspection is warranted, while keeping the Policy Gate as the sole authorization authority.

* **Additional Action-Intent Validation:** Validate whether the proposed action is semantically consistent with the user's original task, reducing the gap between "within authorized scope" and "actually intended by the user."

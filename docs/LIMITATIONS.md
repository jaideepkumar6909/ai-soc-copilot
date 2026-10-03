# Limitations and supported scope

| Area | Implemented | Limitations |
| --- | --- | --- |
| Input | Normalized SSH JSON/JSONL; narrow Wazuh per-event adapter | No live collection, generic syslog parser, Windows events, or completeness guarantee |
| Correlation | Host/user/IP grouping and rolling failure window | No cross-account spray detection, distributed-source correlation, or behavioral baseline |
| Prioritization | Deterministic low/medium/high review order | Not compromise probability; slow attacks and valid stolen credentials can be below threshold |
| AI | Optional Claude structured reports | Hallucinations, unsupported inferences, and category disagreements remain possible |
| Validation | JSON shape, limits, and existing evidence IDs | No semantic proof of claims, citation completeness, or correct advice |
| Playbooks | Two local documents selected by signal | No vector search, external knowledge retrieval, or independently validated policy engine |
| Injection handling | Untrusted-data instructions; two live test variants | No general prompt-injection guarantee; schema constraints do not enforce truthful reasoning |
| Response | Advisory next steps and stored analyst decisions | No real blocking, account changes, tickets, notifications, or response automation |
| Persistence | Local SQLite with review snapshots | No tamper resistance, encryption at rest, retention policy, or multi-user access controls |
| Interface | Local Streamlit dashboard | No application authentication; not intended for internet exposure |
| Evaluation | Synthetic fixtures and recorded live run | No representative dataset, independent labels, or accuracy/time-saving metric |

## Known issues in this release

1. Model assessments can differ from rule assessments without an explicit dashboard
   disagreement banner. Both values are retained in exported case/report data.
2. The model can misdescribe the reason for a priority even when the priority field
   is correct. The host-injection evaluation demonstrates this.
3. The prompt requests supporting citations, but validation checks only ID existence.
4. Missing telemetry can lead to disproportionate escalation advice.
5. The upload control may display Streamlit's larger default upload allowance while
   application validation enforces 2,000,000 bytes. The application limit is authoritative.
6. The evaluation runner writes the full result only after the run. Interruption can
   leave an empty output file and lose completed in-memory responses; no resume exists.
7. A rejected new model response can leave a previous report displayed in the same
   session. Check errors and model/prompt metadata before treating it as a new result.
8. Dependencies pin Streamlit, not its full dependency tree. Environment recreation
   can change transitive versions. No full dependency/security audit was performed.

## Data handling

Normalized names, IPs, hosts, timestamps, and selected playbooks are transmitted when
AI analysis is explicitly requested. The application does not redact or anonymize
them. Exported reports and SQLite snapshots can contain sensitive investigation data.
Provider-side handling is governed by the user's API account terms; this project
makes no provider retention guarantee. Keep private data outside the public repository.

## Intended use

Learning, a portfolio demonstration, and experiments on synthetic or authorized lab
data. Analyst review is required. Production use would require authentication,
authorization, data protection, secure deployment, operational monitoring, broader
testing, and independently validated detection/response procedures.

# AI SOC Copilot

**SSH alert triage with deterministic detection, evidence-linked Claude reports, and analyst review.**

A local Python/Streamlit portfolio prototype that turns SSH authentication events into
reviewable cases. Rules identify failure bursts; an optional LLM drafts findings,
possible explanations, missing evidence, and recommended investigation steps.
No model-generated commands or containment actions are executed.

**Status:** working prototype using synthetic data. Not a production SOC platform.
Built with AI coding assistance; evaluated through local tests and live model runs.

## What it demonstrates

- Event validation, normalization, deduplication, and rolling-window correlation.
- A clear distinction between alert priority and proof of compromise.
- Claude integration with structured JSON output and local citation-ID validation.
- Explicit consent before a dashboard request sends case data to the provider.
- Testing of malicious instructions embedded in log fields.
- Local analyst decisions with rationale and report snapshots in SQLite.
- An evaluation that records failures and limitations instead of claiming perfect accuracy.

## Evaluation snapshot

On **October 3, 2026**, one live run with `claude-sonnet-4-6` and prompt
`ssh-review-v2` produced eight reports:

| Check | Observed result |
| --- | --- |
| Expected rule priority | 8/8 |
| Valid report schema and existing citation IDs | 8/8 |
| Expected model review category | 7/8 |
| Combined automated case checks | 7/8 |
| Embedded instruction followed in the two tested injection cases | Neither observed |

The slow-retry report differed from the expected review category and recommended
excessive escalation when telemetry was missing. Review also found an incorrect
explanation of high priority in the host-injection report. **These checks do not
measure detection accuracy, citation entailment, or general injection resistance.**

Read the [evaluation report](docs/EVALUATION.md), [raw synthetic run](docs/evaluation/live-v2.json),
and [limitations](docs/LIMITATIONS.md). The two duplicate/low-volume inputs normalize
to the same case: eight scenarios are not eight independent model inputs.

## Quick start

Requires Python 3.11 or newer. From the repository directory on Mac/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address 127.0.0.1
```

Open http://127.0.0.1:8501. The three built-in demos run without an API key.
Press **Control+C in Terminal** to stop the server. Bind to loopback: this app has
no application login, role permissions, or production deployment configuration.

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

### Offline CLI and tests

These commands use Python's standard library. The dashboard test requires Streamlit
and reports a skip when it is unavailable.

```bash
python3 cli.py data/suspicious.jsonl
python3 -m unittest discover -s tests -v
python3 evaluate.py --output local/evaluation-offline.json
```

Offline evaluation checks rules and evaluation plumbing, not Claude behavior.
Output files are never overwritten; choose a new filename when repeating a run.

## Optional Claude analysis

Choose a model available to your Anthropic API account. API billing is separate
from a chat subscription. The recorded evaluation used `claude-sonnet-4-6`;
availability in other accounts is not guaranteed.

In Mac/Linux Terminal, run `bash` first if using zsh. Activate the virtual environment
in that shell. Run the following commands **one at a time**. At the key prompt, paste
only your key and press Enter; the characters are hidden.

```bash
read -s -p "Anthropic API key: " ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY
export ANTHROPIC_MODEL="claude-sonnet-4-6"
python -m streamlit run app.py --server.address 127.0.0.1
```

The application reads environment variables; it does not automatically load `.env`.
Never put credentials in source code, exported examples, screenshots, or commits.

Expand **Optional LLM analysis**, review the disclosure, select the consent checkbox,
and click **Generate AI investigation**. One request is made per click with a
3,000-output-token cap and no automatic retries. Input tokens also affect cost.
Token usage is saved; dollar cost is not calculated.

The request contains normalized event IDs, timestamps, account names, hostnames,
IPs, case aggregates, and the selected playbook. These are **not anonymized**.
Raw log-message fields are not included. The key is used as an authentication header,
not inserted into the model prompt. Use synthetic or explicitly authorized lab data.

To explicitly send the eight synthetic evaluation cases to Anthropic:

```bash
python evaluate.py --live --output local/evaluation-live.json
```

This incurs API charges. The current runner prints the summary after all cases;
it may be silent for several minutes. Failed requests are recorded in the output.

## Detection behavior

Events are grouped by host, account, and source IP. A gap greater than ten minutes
starts a new case. Detection uses an inclusive rolling ten-minute window:

| Condition | Priority | Rule review category |
| --- | --- | --- |
| At least five failures preceding a success within the window | High | `needs_review` |
| At least five failures within the window, without that success condition | Medium | `needs_review` |
| Otherwise | Low | `insufficient_evidence` |

Priority is a review order, not a compromise probability. Low volume is not proof
of safety. The model's assessment can disagree with the rule category; the current
dashboard does not explicitly flag that disagreement. No assessment executes actions.

## Supported input

Upload a JSON array or JSONL containing events with these fields:

```json
{"id":"event-001","timestamp":"2026-10-02T13:00:00Z","host":"ubuntu-lab","user":"labuser","src_ip":"192.0.2.44","event_type":"ssh_failure"}
```

`event_type` is `ssh_failure` or `ssh_success`. All six fields are nonempty strings
of at most 256 characters. Timestamps require a timezone and are normalized to UTC.
IPs must parse as addresses. Identical repeated IDs are deduplicated; conflicting
IDs are rejected. Input limits are 2,000,000 bytes and 10,000 rows; live model analysis
accepts at most 200 events per case, without silent truncation.

A narrow Wazuh file adapter accepts per-event records with `id`, `timestamp`,
`agent.name`, `data.srcip`, `data.dstuser`, and `rule.groups` containing `sshd` plus
`authentication_failed` or `authentication_success`. Other groups are counted as
skipped. This is exported-file import, not a live Wazuh connection. Aggregated alerts
are not expanded into attempts, and counts depend on export completeness.

## Project map

| Path | Purpose |
| --- | --- |
| `core.py` | Parsing, correlation, priority, playbook selection, SQLite reviews |
| `llm.py` | Claude request, structured output, response validation |
| `app.py` | Streamlit dashboard |
| `cli.py` | Offline JSON reports |
| `evaluate.py` | Eight synthetic scenarios and opt-in live evaluation |
| `data/` | Three dashboard demonstrations |
| `playbooks/` | Two rule-selected investigation guides |
| `tests/` | Unit, mocked API, evaluation, and dashboard tests |
| `docs/` | Architecture, support scope, evaluation, limitations, validation |
| `local/` | Runtime reports and review database; excluded from Git |

See [architecture](docs/ARCHITECTURE.md), [support](SUPPORT.md),
[security considerations](SECURITY.md), and [contributing](CONTRIBUTING.md).

## Next development priorities

1. Display rule-derived facts separately from model interpretations and flag disagreement.
2. Add claim-level support review and proportionality checks without disguising model failures.
3. Collect authorized SSH logs from a real lab and validate the import adapter.
4. Evaluate separately labeled, held-out scenarios and repeat injection tests.

No production deployment, accuracy percentage, efficiency gain, or hiring improvement
has been established. This repository documents a prototype and the evidence behind it.

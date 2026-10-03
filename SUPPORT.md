# Support

This is a learning project with best-effort support and no response-time commitment.
It is not a managed security service or an incident-response contact.

## Supported usage

- Python 3.11+ source; local Mac/Linux setup instructions and Windows commands.
- Local Streamlit dashboard with the pinned dependency.
- Standard-library offline CLI and evaluation.
- Synthetic normalized SSH events and the documented narrow Wazuh file adapter.
- Optional Anthropic API with a model available to the user's account.

The project owner demonstrated the dashboard and live calls on macOS with Python
3.11. The release packaging environment runs standard-library tests separately;
Windows has not been verified. See docs/VALIDATION.md for exact results.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Missing Streamlit | Activate `.venv`, then `python -m pip install -r requirements.txt` |
| Terminal busy running app | Control+C in that Terminal; closing the browser does not stop it |
| No Optional LLM analysis | Scroll below the event table |
| Missing API configuration | Export key and model in the same shell that launches the app |
| HTTP API error | Check key, model access, billing, and workspace configuration; do not share the key |
| Certificate verification error on Mac | With certifi installed, run `export SSL_CERT_FILE="$(python -m certifi)"` in the launching shell; never disable certificate checks |
| Invalid model output | Keep the rules-only result, inspect the error, and preserve the failing fixture |
| Evaluation file exists | Use a new output filename; existing results are protected |
| Live evaluation seems silent | It prints after all eight requests; no progress display is implemented |
| 7/8 checks passed | Read the per-case checks; a category mismatch is not an installation failure |

For a reproducible bug, open a repository issue with OS, Python version, exact command,
expected/actual behavior, and a minimal synthetic input. Remove names, credentials,
private logs, and tokens. Do not upload the review database.

For security-sensitive reports, follow SECURITY.md instead of posting details publicly.

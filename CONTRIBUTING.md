# Contributing

Use synthetic fixtures and keep the project focused on evidence-based SSH triage.
For a behavioral change, describe the failure it fixes and add a regression test
that would fail without the change. Run `python -m unittest discover -s tests -v`.

Do not commit API keys, private logs, local databases, or environment directories.
Do not add automatic containment or external messaging without a separately designed
authorization mechanism. Document provider calls and data disclosure changes.

For model changes, retain original evaluation outputs, record the prompt version,
and report both improvements and regressions. Keep fixture development separate from
held-out assessment before claiming general performance.

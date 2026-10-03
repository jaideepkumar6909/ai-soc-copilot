# Release validation — October 3, 2026

The packaged source was tested with `python3 -m unittest discover -s tests -v`:
**27 passed, 1 skipped, 28 total.** The skipped test is the Streamlit AppTest
dashboard/scenario-switch check because Streamlit is not installed in the packaging
environment. No current full dashboard test pass is claimed.

Passing tests cover parsing, duplicate handling, timestamp validation, narrow Wazuh
mapping, rolling windows, account separation, SQLite snapshots, mocked API calls,
schema requests, JSON wrappers, refusal/truncation handling, duplicate JSON fields,
unknown citation rejection, and offline/provider-failure evaluation behavior.

The offline evaluator passed all eight cases during development. The project owner
also supplied a screenshot of 8/8 offline passes on their Mac. The recorded live
run passed 7/8 combined checks; see EVALUATION.md. Live output quality is distinct
from code unit tests. No live API calls were made by the packaging environment.

The owner demonstrated the dashboard and API integration in screenshots earlier
in this session. These demonstrations are not load tests or security audits.

Release checks additionally inspect local Markdown links, JSON parseability, and
the archive's allowlisted contents. Secret-pattern checks cannot guarantee absence
of every possible secret. The release excludes local databases, environment files,
API credentials, old backups, and personal desktop/browser screenshots.

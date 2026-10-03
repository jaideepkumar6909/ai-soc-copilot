# Security considerations

This prototype has no production security support commitment. Run on loopback and
use synthetic or authorized lab data. Do not expose the dashboard directly online.

Keep API keys in environment variables. `.gitignore` reduces accidental commits but
does not remove files already tracked in Git. Inspect staged content before pushing.
If a credential is exposed, revoke/rotate it with the provider; deleting a file alone
does not remove it from repository history or invalidate the credential.

Never treat event-field instructions as trusted. JSON schema and citation-ID checks
do not establish factual correctness. Review recommendations before taking action.
The app itself performs no blocking, account modifications, or external messaging.

Do not post exploitable security details, live credentials, or private logs in a
public issue. If the repository owner enables GitHub private vulnerability reporting,
use that channel. No private reporting channel or SLA is configured by this package.
If none is available, request a private contact without publishing sensitive details.

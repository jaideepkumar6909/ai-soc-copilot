# PB-SSH-01: Authentication burst
1. Verify event times, account, host, and source IP. A failed login is an event; a correlated burst may warrant an alert.
2. Establish whether the owner recognizes the attempts. Repeated failures followed by success can be either legitimate recovery or unauthorized access.
3. Request post-login process, privilege, session, and network activity. Do not claim these were checked when only authentication logs are available.
4. Escalate if the activity is unrecognized or supported by additional suspicious evidence.
5. Propose containment only after review. This application does not execute account or network changes.

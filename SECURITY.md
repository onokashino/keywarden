# Security policy

Keywarden stores passwords, so security reports get priority over everything else.

## Reporting

Use **GitHub private vulnerability reporting**: the "Report a vulnerability" button on the
[Security tab](https://github.com/onokashino/keywarden/security). Please do not open public
issues for vulnerabilities. You should get a reply within a week.

## Scope

In scope: anything that lets another user, process, website or network peer read secrets,
unlock or modify the database, or bypass a confirmation. For example:

- the daemon sockets or named pipes accepting a foreign user;
- the browser extension filling or revealing credentials for the wrong site;
- secrets ending up in logs, crash dumps, swap or clipboard history;
- a save that corrupts or silently loses database content.

Out of scope: an attacker who already runs code as your user while the database is unlocked
(they can read process memory or the screen; no local password manager defends against that).

## Supported versions

Only the latest release receives fixes.

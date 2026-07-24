# Security policy

Do not submit credentials, ACVP client state, private keys, TOTP seeds, JWTs, Authorization headers, raw `secure-datastore` content, or unsanitized validation sessions.

Public evidence must be generated from the repository's allowlist exporter into a new empty staging directory, pass automated scans, and receive a file-by-file human review.

If sensitive data is committed, stop distribution, rotate the affected credential, remove it from the complete Git history, and document the incident. Deleting it in a later commit is not sufficient.

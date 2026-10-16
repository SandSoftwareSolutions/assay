# Security policy

Please report vulnerabilities privately: use the "Report a vulnerability" button on the Security tab
of this repository, or email info@sandsoftwaresolutions.nl. Include the version
(`hallmark version`), what you did and what you expected. Please give a reasonable time to fix the
problem before disclosing it.

Things that count as vulnerabilities: a manifest that makes `check` read, write or hash outside the
folder; a crafted manifest or key file that crashes the program; a way to make a signed manifest verify
after its content was changed; unexpected disclosure of file contents.

See [docs/security-model.md](docs/security-model.md) for the intended guarantees and their limits.

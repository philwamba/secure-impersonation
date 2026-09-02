# Security Policy

Report suspected vulnerabilities privately to the package maintainer. Include the affected version, reproduction steps, impact and any suggested mitigation.

Do not open a public issue for authentication bypasses, privilege escalation, session fixation, impersonation-target bypasses or audit-log disclosure until a patched release is available.

Security fixes receive a patch release for supported versions. Applications should run `composer audit --locked`, keep Laravel and PHP supported, and test authorization and session behavior before upgrading.

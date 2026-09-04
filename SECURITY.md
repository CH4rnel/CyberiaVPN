# Security policy

Cyberia VPN is in early development and is not ready to protect production
traffic. Please do not treat current builds as a security product.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security advisory flow for this repository and include the affected revision,
impact, reproduction steps and any proposed mitigation. Avoid accessing data
that is not yours and stop testing if it could disrupt a service.

The project will acknowledge a complete report, triage its severity and agree
on a coordinated disclosure timeline before details become public.

## Scope and expectations

- Never commit credentials, private keys or production configuration.
- Security scanners may target only owned or explicitly authorized assets.
- User traffic contents and browsing history must not enter logs or telemetry.
- Security-sensitive changes require tests and review of failure behavior.
- A compromised node is drained, revoked and rebuilt instead of trusted after
  an unverifiable in-place repair.

# Contributing to Cyberia VPN

Cyberia VPN is developed in small, reviewable increments. Security-sensitive
behavior must be demonstrated by tests rather than assumed from an
implementation.

## Test-driven development

Critical routing, transport, identity, authorization, billing and
configuration logic follows the red-green-refactor cycle:

1. **Red:** add a focused test that describes one externally observable rule
   and confirm that it fails for the expected reason.
2. **Green:** implement the smallest safe change that satisfies the rule.
3. **Refactor:** remove duplication and improve names or boundaries while the
   test suite remains green.

Do not commit a deliberately failing red phase to `master`. Preserve the TDD
cycle in the working process and deliver each completed behavior as a green,
atomic commit. Bugs receive a regression test before their fix.

## Extreme Programming practices

- Prefer the simplest design that meets the current acceptance criteria.
- Integrate continuously and keep every commit buildable.
- Refactor continuously instead of accumulating a separate cleanup phase.
- Keep ownership collective through tests, ADRs and readable interfaces.
- Pair on security-critical, unsafe, cryptographic and migration changes.
- Release small increments and use real feedback before adding speculative
  abstractions or machine learning.
- Work at a sustainable pace; urgency does not waive quality or security gates.

## SOLID boundaries

SOLID principles guide component boundaries without forcing class-heavy design:

- **Single responsibility:** transport adapters connect; routing policy selects;
  registries store trusted node metadata; handlers translate HTTP.
- **Open/closed:** new transports implement the shared contract without adding
  protocol branches throughout clients.
- **Liskov substitution:** every adapter obeys the same timeout, cancellation,
  health and teardown semantics.
- **Interface segregation:** consumers depend on narrow reader, writer, signer
  or verifier capabilities rather than broad service objects.
- **Dependency inversion:** domain logic receives clocks, stores and external
  providers through explicit interfaces; infrastructure depends on the domain.

Prefer plain values and functions when an interface would have only one stable
consumer. An abstraction must protect a real boundary, not predict one.

## Definition of done

A change is complete when, in proportion to its risk:

- acceptance behavior and failure paths are covered by tests;
- `make check` passes;
- errors are typed or carry useful context and are never silently ignored;
- cancellation, deadlines and resource ownership are explicit;
- secure defaults, privacy and backward compatibility were reviewed;
- public contracts and architecture decisions are documented;
- operational code exposes safe health signals without user payloads;
- the commit is focused and its English message explains the outcome.

Integration, fuzz, load, soak, security, rollback and disaster-recovery checks
become mandatory as soon as the affected component exists. A production claim
requires every gate listed in the roadmap, not only unit-test coverage.

## Local checks

```sh
make check
```

Formatting is automatic:

```sh
cargo fmt --all
gofmt -w services
```

# Agent instructions

These rules apply to every change in this repository, made by a person or by a coding agent.

## No temporary documents

The repository keeps only lasting documents: the README, an ARCHITECTURE document (or a reference that plays its part), AGENTS.md and CLAUDE.md, a build and release guide, CHANGELOG, LICENSE, NOTICE and third-party notices, and the images a README shows. Never commit a design draft, plan, review, assessment, investigation write-up, specification draft, gap file or notes file. Keep those outside the repository; when one holds something of lasting value, fold that part into the README or the architecture document instead.

## Standalone conventional commit messages

Every commit message starts with a conventional type: `fix:`, `feat:`, `chore:`, `ci:`, `docs:`, `refactor:`, `test:` or `perf:` (a breaking change is `feat!:` or `fix!:`, or carries a `BREAKING CHANGE:` note). The rest says in plain sentences what the change does and why, in terms of the code itself. A message never names a plan, design document, review, tracker item, stage or phase, decision or ruling, finding or gap id, or agent lane, and cites no file outside the repository.

Good: `fix: charge idempotency keys are scoped by partition, and an empty key is refused`

Not: `fix: billing review finding B1 (review round 1)`

# Security Policy

## Supported scope

This repository is currently a single active line on `main` plus open feature branches under review.

## Reporting

Please avoid posting live secrets or exploit payloads in public issues.

Instead, open a private report with:

- affected file or code path
- sanitized reproduction steps
- observed impact
- recommended remediation if known

## Response goals

- acknowledge receipt quickly
- verify severity and impact
- land minimal reversible fixes first
- add regression tests for confirmed issues
- document residual risk in `docs/security-audit.md`

## Current security posture

- no network access required for scans
- no shell execution inside the scanner
- no external runtime dependencies
- least-privilege CI workflows

## Out of scope

False positives from heuristic scanning are quality issues unless they enable a security bypass or suppression failure.

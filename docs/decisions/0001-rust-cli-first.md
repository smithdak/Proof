# ADR-0001: Rust core and CLI-first interface

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Proof needs deterministic behavior, a portable single-binary local mode, strong type and memory safety, predictable resource use, and interfaces suitable for people and agents. A UI-first implementation would make machine operation secondary and risk privileged UI-only flows.

## Decision

Implement the domain and application core in Rust. Make `proof` the first complete product interface. HTTP, SDK, MCP, and web interfaces invoke the same application contracts and do not own domain behavior.

Use Rust 2024 Edition and pin the current patched stable toolchain for CI and release builds.

## Consequences

- Domain invariants can use Rust types and exhaustive state modeling.
- Local operation can ship as a portable binary.
- CLI structured input and output become early compatibility surfaces.
- Web UI development follows, rather than defines, application behavior.
- Contributors need Rust expertise.
- Dynamic extension must use explicit protocols instead of unstable Rust ABI plugins.

## Alternatives considered

- **TypeScript-first:** faster web iteration but weaker fit for the deterministic portable core and local single binary.
- **Go-first:** strong operational fit, but Rust better matches the intended correctness and reusable domain-library goals.
- **Web-console first:** rejected because it would repeat the UI-primary architecture Proof is intended to replace.

## Verification

- Domain crates cannot depend on interface frameworks.
- Every application operation is invocable through structured CLI mode.
- No capability is accepted with only a graphical implementation.

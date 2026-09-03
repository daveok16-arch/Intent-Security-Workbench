# Intent Security Workbench (Phase 0)

> **Foundational Architecture for Authorized Security Research**

Intent Security Workbench is a modular, production-grade security research platform supporting authorized multi-program research across bounty platforms (Immunefi, HackenProof, Cantina, HackerOne, Custom), blockchain ecosystems (EVM, Solana/Rust, Clarity/Stacks, Move), and Web/API targets.

## Core Non-Negotiable Invariants

1. **No Fake Findings / No Synthetic Scanners**: The system never claims an engine executed, a vulnerability was verified, or a proof was generated unless real machine-verifiable evidence was generated.
2. **Deterministic Evidence Hashing**: Every artifact is assigned a cryptographic SHA-256 digest calculated over raw payload bytes.
3. **Strict 10-State Machine**: Findings follow a validated transition path (`CANDIDATE` → `ANALYZING` → `VERIFICATION_REQUIRED` → `TESTING` → `REPRODUCED` → `VALIDATED` → `CONFIRMED`).
4. **Engine Availability Truthfulness**: Unavailable binaries return explicit `NOT_INSTALLED / UNAVAILABLE` statuses.

## Quickstart

### Prerequisites
- Node.js 20+
- (Optional) Docker & Docker Compose

### Running the Workbench
```bash
# Install dependencies
npm install

# Start development server on port 3000
npm run dev

# Run full test suite
npm test
```

### Running with Docker Compose
```bash
docker-compose up --build
```

# Deterministic Intelligence Orchestrator (DIO)

A containment and governance system that enforces capability-based security for autonomous agents, ensuring no action can occur without explicit authorization.

## Overview

DIO governs the execution of artificial intelligence workflows in enterprise, regulatory, and safety-critical environments. It ensures that intelligence execution is reproducible, auditable, governed by strict policy enforcement, and deterministic with explicit modeling of determinism boundaries.

DIO operates on Execution Graphs: immutable, declarative descriptions of intelligence runs that include inputs, models, tool interfaces, policy constraints, allowed side effects, failure handling, determinism boundaries, and output commitments.

## Architecture

<pre>
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   Execution     │    │   Policy         │    │  Determinism       │
│   Graph         │───▶│   Engine         │───▶│  Tracker           │
│                 │    │                  │    │                    │
│ - Nodes         │    │ - Rules          │    │ - Node types       │
│ - Metadata      │    │ - Enforcement    │    │ - Determinism      │
│ - Hash          │    │ - Violations     │    │   tracking         │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│  Execution      │    │  Execution       │    │  Execution         │
│  Engine         │───▶│  Transcript      │───▶│  Replay            │
│                 │    │                  │    │                    │
│ - Graph         │    │ - Entries        │    │ - Verification     │
│ - Policy        │    │ - Integrity      │    │ - Replay           │
│ - Execution     │    │ - Hashing        │    │ - Validation       │
│   tracking      │    │ - Signing        │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   Adapters      │    │  Storage         │    │  External          │
│                 │    │                  │    │  Systems           │
│ - Data          │    │ - Graphs         │    │ - Models           │
│ - Compute       │    │ - Transcripts    │    │ - Tools            │
│ - Scheduling    │    │ - Policies       │    │ - Orchestration    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
</pre>

## Components

### Execution Graphs
Immutable, declarative descriptions of intelligence workflows including inputs and outputs, model calls and tool interfaces, policy constraints, determinism boundaries, and side effect specifications.

### Policy Engine
Enforces governance policies before execution: model access restrictions, tool invocation limits, resource usage caps, data egress controls, retry behavior rules, cost ceilings, and human approval gates.

### Execution Engine
Manages the lifecycle of intelligence workflows. Validates graphs and enforces policies, executes nodes deterministically in topological order, tracks side effects and entropy sources, and produces cryptographically verifiable transcripts.

### Execution Transcript
Append-only, tamper-evident records of execution. Provides a complete audit trail of all actions with cryptographic hashing for integrity verification, signed entries for authenticity, and replayable execution logs.

### Determinism Tracker
Explicitly models determinism characteristics across fully deterministic nodes, bounded nondeterministic nodes, and external nondeterministic nodes. Uses hash-based verification of determinism boundaries.

## Build
```bash
cargo build --release
```

## Test
```bash
cargo test
```

## Run
```bash
./dio
```

On Windows:
```bash
.\dio.exe
```

## Design Principles
1. **Determinism First** - All execution behavior must be explicitly modeled and documented. No implicit assumptions about model determinism.
2. **Governance Over Optimization** - Policy enforcement happens before execution, not after. All decisions are auditable and defensible.
3. **Cryptographic Integrity** - Every component is designed with cryptographic verification in mind - from graphs to transcripts to execution logs.
4. **Explicit State Management** - No hidden global state. All execution state is explicit and traceable through the transcript system.
5. **Composability** - Each module can be replaced or extended independently without affecting core functionality.

## Requirements
- Rust 1.56+
- Cryptographically secure hashing (SHA-256)
- Deterministic execution semantics
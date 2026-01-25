# Deterministic Intelligence Orchestrator (DIO)

## One-sentence value proposition

A production-grade control plane for deterministic, auditable, and policy-bounded intelligence execution.

## Overview

The Deterministic Intelligence Orchestrator (DIO) is a control plane designed to govern the execution of artificial intelligence workflows in enterprise, regulatory, and safety-critical environments. Unlike workflow engines or agent frameworks, DIO focuses on ensuring that intelligence execution is:

- **Reproducible**: Every execution can be replayed with equivalent results
- **Auditable**: Complete, cryptographically verifiable records of all actions
- **Governed**: Strict policy enforcement before any execution begins
- **Deterministic**: Explicit modeling of determinism boundaries

DIO operates on **Execution Graphs**, not pipelines. An execution graph is an immutable, declarative description of an intelligence run that includes inputs, models, tool interfaces, policy constraints, allowed side effects, failure handling, determinism boundaries, and output commitments.

## Architecture diagram
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

## Core Components

### 1. Execution Graphs
Immutable, declarative descriptions of intelligence workflows that include:
- Inputs and outputs
- Model calls and tool interfaces
- Policy constraints
- Determinism boundaries
- Side effect specifications

### 2. Policy Engine
Enforces governance policies before execution:
- Model access restrictions
- Tool invocation limits
- Resource usage caps
- Data egress controls
- Retry behavior rules
- Cost ceilings
- Human approval gates

### 3. Execution Engine
Manages the lifecycle of intelligence workflows:
- Validates graphs and enforces policies
- Executes nodes deterministically in topological order
- Tracks side effects and entropy sources
- Produces cryptographically verifiable transcripts

### 4. Execution Transcript
Append-only, tamper-evident records of execution:
- Complete audit trail of all actions
- Cryptographic hashing for integrity verification
- Signed entries for authenticity
- Replayable execution logs

### 5. Determinism Tracker
Explicitly models determinism characteristics:
- Fully deterministic nodes
- Bounded nondeterministic nodes
- External nondeterministic nodes
- Hash-based verification of determinism

## Usage

```rust
use dio::{
    IntelligenceOrchestrator, PolicyEngine, PolicyRule, PolicyType,
    ExecutionGraph, GraphNode, NodeType, Determinism,
};
use std::collections::HashMap;

// Create policy engine and add rules
let mut policy_engine = PolicyEngine::new();

let mut conditions = HashMap::new();
conditions.insert("allowed_models".into(), serde_json::json!(["gpt-3.5"]));

policy_engine.add_rule(PolicyRule::new(
    "model_access".to_string(),
    PolicyType::ModelAccess,
    conditions,
    vec!["allow".to_string()],
    "Only allow gpt-3.5 model".to_string()
).unwrap());

// Create orchestrator
let orchestrator = IntelligenceOrchestrator::new(policy_engine, 1000);

// Define execution graph
let mut node_data = HashMap::new();
node_data.insert("model_name".into(), serde_json::json!("gpt-3.5"));

let node1 = GraphNode::new(
    "model_call_1".to_string(),
    NodeType::ModelCall,
    node_data,
    Determinism::Deterministic,
    vec![],
    HashMap::new(),
).unwrap();

let graph = ExecutionGraph::new(
    vec![node1],
    HashMap::new(),
    "1.0".to_string()
).unwrap();

// Submit and execute
let execution_id = orchestrator.submit_graph(graph).unwrap();
let transcript = orchestrator.execute(&execution_id).unwrap();

// Verify execution
let is_valid = orchestrator.verify(&execution_id).unwrap();
```

## Design Principles
1. **Determinism First**
All execution behavior must be explicitly modeled and documented. No implicit assumptions about model determinism.
2. **Governance Over Optimization**
Policy enforcement happens before execution, not after. All decisions are auditable and defensible.
3. **Cryptographic Integrity**
Every component is designed with cryptographic verification in mind - from graphs to transcripts to execution logs.
4. **Explicit State Management**
No hidden global state. All execution state is explicit and traceable through the transcript system.
5. **Composability**
Each module can be replaced or extended independently without affecting core functionality.

## What DIO Is Not
DIO is not:
- A workflow engine
- An agent framework
- A model training platform
- A data movement tool
- An autonomous goal-seeking system

## Requirements
- Rust 1.56+
- Strong typing throughout
- Comprehensive unit tests
- Immutable data structures where appropriate
- Explicit error handling with clear failure messages
- Cryptographically secure hashing (SHA-256)
- Deterministic execution semantics
- Policy-driven governance model

## Security Considerations
DIO implements cryptographic guarantees including:
- Execution graph hashing
- Transcript hashing
- Optional signing of runs
- Tamper-evident logs
- Replay verification
- Policy validation before execution

The system uses established cryptographic primitives to ensure correctness and traceability over novelty.

## Installation
Install DIO using cargo:

```bash
cargo add dio
```
Or install from source:

```bash
git clone https://github.com/pngen/dio.git
cd dio
cargo build
```

## Development
To contribute to DIO, run tests with:

```bash
cargo test
```
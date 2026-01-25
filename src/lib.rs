#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]
//! # Deterministic Intelligence Orchestrator (DIO)
//!
//! Production-grade control plane for deterministic, auditable,
//! and policy-bounded intelligence execution.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

// =============================================================================
// ERROR TYPES
// =============================================================================

#[derive(Debug, Error)]
pub enum DioError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Policy violation [{policy_type}]: {message}")]
    PolicyViolation {
        message: String,
        policy_type: PolicyType,
        details: HashMap<String, serde_json::Value>,
    },

    #[error("Execution error: {0}")]
    Execution(String),

    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Integrity error: {0}")]
    Integrity(String),

    #[error("State error: {0}")]
    State(String),
}

pub type DioResult<T> = Result<T, DioError>;

// =============================================================================
// ENUMS - With Display instead of ToString (idiomatic Rust)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    ModelCall,
    ToolCall,
    Decision,
    Retry,
    SideEffect,
    Output,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModelCall => write!(f, "model_call"),
            Self::ToolCall => write!(f, "tool_call"),
            Self::Decision => write!(f, "decision"),
            Self::Retry => write!(f, "retry"),
            Self::SideEffect => write!(f, "side_effect"),
            Self::Output => write!(f, "output"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    ModelAccess,
    ToolAccess,
    ResourceLimits,
    DataEgress,
    RetryBehavior,
    SideEffects,
    CostCeiling,
    HumanApproval,
}

impl std::fmt::Display for PolicyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModelAccess => write!(f, "model_access"),
            Self::ToolAccess => write!(f, "tool_access"),
            Self::ResourceLimits => write!(f, "resource_limits"),
            Self::DataEgress => write!(f, "data_egress"),
            Self::RetryBehavior => write!(f, "retry_behavior"),
            Self::SideEffects => write!(f, "side_effects"),
            Self::CostCeiling => write!(f, "cost_ceiling"),
            Self::HumanApproval => write!(f, "human_approval"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    Submission,
    NodeStart,
    NodeComplete,
    NodeFailure,
    Failure,
    Completion,
    PolicyViolation,
}

impl std::fmt::Display for EntryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submission => write!(f, "submission"),
            Self::NodeStart => write!(f, "node_start"),
            Self::NodeComplete => write!(f, "node_complete"),
            Self::NodeFailure => write!(f, "node_failure"),
            Self::Failure => write!(f, "failure"),
            Self::Completion => write!(f, "completion"),
            Self::PolicyViolation => write!(f, "policy_violation"),
        }
    }
}

/// Type-safe determinism classification (replaces stringly-typed version)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Determinism {
    Deterministic,
    BoundedNondeterministic,
    ExternalNondeterministic,
}

impl std::fmt::Display for Determinism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deterministic => write!(f, "deterministic"),
            Self::BoundedNondeterministic => write!(f, "bounded_nondeterministic"),
            Self::ExternalNondeterministic => write!(f, "external_nondeterministic"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Blocked,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Blocked => write!(f, "blocked"),
        }
    }
}

// =============================================================================
// GRAPH NODE - Type-safe determinism
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: NodeType,
    pub data: HashMap<String, serde_json::Value>,
    pub determinism: Determinism,
    pub dependencies: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl GraphNode {
    pub fn new(
        id: String,
        node_type: NodeType,
        data: HashMap<String, serde_json::Value>,
        determinism: Determinism,
        dependencies: Vec<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> DioResult<Self> {
        if id.is_empty() {
            return Err(DioError::Validation("Node ID cannot be empty".into()));
        }
        // Validate ID format (alphanumeric + underscore)
        if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err(DioError::Validation(format!(
                "Node ID '{}' contains invalid characters",
                id
            )));
        }

        Ok(Self {
            id,
            node_type,
            data,
            determinism,
            dependencies,
            metadata,
        })
    }
}

// =============================================================================
// EXECUTION GRAPH - Deterministic hashing via sorted canonical form
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGraph {
    pub nodes: Vec<GraphNode>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub version: String,
}

impl ExecutionGraph {
    pub fn new(
        nodes: Vec<GraphNode>,
        metadata: HashMap<String, serde_json::Value>,
        version: String,
    ) -> DioResult<Self> {
        if nodes.is_empty() {
            return Err(DioError::Graph("Graph must contain at least one node".into()));
        }

        let mut seen_ids = HashSet::new();
        for node in &nodes {
            if !seen_ids.insert(&node.id) {
                return Err(DioError::Graph(format!("Duplicate node ID: {}", node.id)));
            }
        }

        Ok(Self { nodes, metadata, version })
    }

    /// Deterministic hash: sorts nodes by ID, sorts all map keys
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_nodes = self.nodes.clone();
        sorted_nodes.sort_by(|a, b| a.id.cmp(&b.id));

        let canonical = serde_json::json!({
            "version": self.version,
            "metadata": Self::sorted_map(&self.metadata),
            "nodes": sorted_nodes.iter().map(|n| self.canonical_node(n)).collect::<Vec<_>>()
        });

        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    fn canonical_node(&self, node: &GraphNode) -> serde_json::Value {
        let mut deps = node.dependencies.clone();
        deps.sort();

        serde_json::json!({
            "id": node.id,
            "type": node.node_type.to_string(),
            "determinism": node.determinism.to_string(),
            "dependencies": deps,
            "data": Self::sorted_map(&node.data),
            "metadata": Self::sorted_map(&node.metadata)
        })
    }

    fn sorted_map(map: &HashMap<String, serde_json::Value>) -> serde_json::Value {
        let mut keys: Vec<_> = map.keys().collect();
        keys.sort();
        let sorted: serde_json::Map<String, serde_json::Value> = keys
            .into_iter()
            .map(|k| (k.clone(), map[k].clone()))
            .collect();
        serde_json::Value::Object(sorted)
    }

    /// Validate: no cycles, no missing deps. Returns detailed error.
    pub fn validate(&self) -> DioResult<()> {
        let node_ids: HashSet<_> = self.nodes.iter().map(|n| n.id.as_str()).collect();

        // Check missing dependencies
        for node in &self.nodes {
            for dep in &node.dependencies {
                if !node_ids.contains(dep.as_str()) {
                    return Err(DioError::Graph(format!(
                        "Node '{}' references missing dependency '{}'",
                        node.id, dep
                    )));
                }
            }
        }

        // Check cycles via DFS
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for node in &self.nodes {
            if let Some(cycle) = self.detect_cycle(&node.id, &mut visited, &mut rec_stack) {
                return Err(DioError::Graph(format!(
                    "Circular dependency detected at node '{}'",
                    cycle
                )));
            }
        }

        Ok(())
    }

    fn detect_cycle(
        &self,
        node_id: &str,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
    ) -> Option<String> {
        if rec_stack.contains(node_id) {
            return Some(node_id.to_string());
        }
        if visited.contains(node_id) {
            return None;
        }

        visited.insert(node_id.to_string());
        rec_stack.insert(node_id.to_string());

        if let Some(node) = self.get_node(node_id) {
            for dep in &node.dependencies {
                if let Some(cycle) = self.detect_cycle(dep, visited, rec_stack) {
                    return Some(cycle);
                }
            }
        }

        rec_stack.remove(node_id);
        None
    }

    pub fn get_node(&self, id: &str) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<&GraphNode> {
        self.nodes.iter().filter(|n| n.node_type == node_type).collect()
    }
}

// =============================================================================
// POLICY RULE
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    #[serde(rename = "type")]
    pub policy_type: PolicyType,
    pub conditions: HashMap<String, serde_json::Value>,
    pub actions: Vec<String>,
    pub description: String,
    #[serde(default)]
    pub priority: u32,
}

impl PolicyRule {
    pub fn new(
        id: String,
        policy_type: PolicyType,
        conditions: HashMap<String, serde_json::Value>,
        actions: Vec<String>,
        description: String,
    ) -> DioResult<Self> {
        Self::with_priority(id, policy_type, conditions, actions, description, 0)
    }

    pub fn with_priority(
        id: String,
        policy_type: PolicyType,
        conditions: HashMap<String, serde_json::Value>,
        actions: Vec<String>,
        description: String,
        priority: u32,
    ) -> DioResult<Self> {
        if id.is_empty() {
            return Err(DioError::Validation("Policy ID cannot be empty".into()));
        }
        if actions.is_empty() {
            return Err(DioError::Validation("Policy must have at least one action".into()));
        }
        if conditions.is_empty() {
            return Err(DioError::Validation("Policy must have conditions".into()));
        }

        // Type-specific validation
        match policy_type {
            PolicyType::ModelAccess => {
                let allowed = conditions.get("allowed_models");
                if !matches!(allowed, Some(v) if v.is_array()) {
                    return Err(DioError::Validation(
                        "MODEL_ACCESS requires 'allowed_models' array".into(),
                    ));
                }
            }
            PolicyType::ToolAccess => {
                let allowed = conditions.get("allowed_tools");
                if !matches!(allowed, Some(v) if v.is_array()) {
                    return Err(DioError::Validation(
                        "TOOL_ACCESS requires 'allowed_tools' array".into(),
                    ));
                }
            }
            PolicyType::CostCeiling => {
                let max_cost = conditions.get("max_cost");
                if !matches!(max_cost, Some(v) if v.is_number()) {
                    return Err(DioError::Validation(
                        "COST_CEILING requires numeric 'max_cost'".into(),
                    ));
                }
            }
            PolicyType::ResourceLimits => {
                let has_limit = ["max_tokens", "max_time_seconds", "max_retries"]
                    .iter()
                    .any(|k| conditions.contains_key(*k));
                if !has_limit {
                    return Err(DioError::Validation(
                        "RESOURCE_LIMITS requires at least one limit".into(),
                    ));
                }
            }
            _ => {}
        }

        Ok(Self {
            id,
            policy_type,
            conditions,
            actions,
            description,
            priority,
        })
    }
}

// =============================================================================
// DETERMINISM TRACKER - Sorted vectors for deterministic hashing
// =============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeterminismTracker {
    deterministic: Vec<String>,
    bounded_nondeterministic: Vec<String>,
    external_nondeterministic: Vec<String>,
}

impl DeterminismTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, node_id: String, determinism: Determinism) {
        let list = match determinism {
            Determinism::Deterministic => &mut self.deterministic,
            Determinism::BoundedNondeterministic => &mut self.bounded_nondeterministic,
            Determinism::ExternalNondeterministic => &mut self.external_nondeterministic,
        };
        if !list.contains(&node_id) {
            list.push(node_id);
        }
    }

    pub fn deterministic_nodes(&self) -> &[String] {
        &self.deterministic
    }

    pub fn bounded_nodes(&self) -> &[String] {
        &self.bounded_nondeterministic
    }

    pub fn external_nodes(&self) -> &[String] {
        &self.external_nondeterministic
    }

    /// Deterministic hash: sorts all lists before hashing
    pub fn hash(&self) -> String {
        let mut det = self.deterministic.clone();
        let mut bounded = self.bounded_nondeterministic.clone();
        let mut external = self.external_nondeterministic.clone();
        det.sort();
        bounded.sort();
        external.sort();

        let canonical = serde_json::json!({
            "deterministic": det,
            "bounded_nondeterministic": bounded,
            "external_nondeterministic": external
        });

        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
        format!("{:x}", hasher.finalize())
    }
}

// =============================================================================
// TRANSCRIPT - Chain-hashed entries for tamper evidence
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub entry_type: EntryType,
    pub timestamp: u64,
    pub sequence: u64,
    pub data: HashMap<String, serde_json::Value>,
    pub prev_hash: String,
}

impl TranscriptEntry {
    fn hash(&self) -> String {
        let canonical = serde_json::json!({
            "entry_type": self.entry_type.to_string(),
            "timestamp": self.timestamp,
            "sequence": self.sequence,
            "data": ExecutionGraph::sorted_map(&self.data),
            "prev_hash": self.prev_hash
        });
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTranscript {
    pub execution_id: String,
    pub graph_hash: String,
    pub created_at: u64,
    entries: Vec<TranscriptEntry>,
    next_sequence: u64,
    chain_head: String,
    pub signature: Option<String>,
    pub determinism_hash: Option<String>,
}

impl ExecutionTranscript {
    pub fn new(execution_id: String, graph_hash: String, timestamp: u64) -> Self {
        Self {
            execution_id,
            graph_hash,
            created_at: timestamp,
            entries: Vec::new(),
            next_sequence: 0,
            chain_head: "genesis".into(),
            signature: None,
            determinism_hash: None,
        }
    }

    pub fn add_entry(&mut self, entry_type: EntryType, data: HashMap<String, serde_json::Value>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = TranscriptEntry {
            entry_type,
            timestamp,
            sequence: self.next_sequence,
            data,
            prev_hash: self.chain_head.clone(),
        };

        self.chain_head = entry.hash();
        self.next_sequence += 1;
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[TranscriptEntry] {
        &self.entries
    }

    /// Verify: sequence continuity, timestamp ordering, chain integrity
    pub fn verify_integrity(&self) -> DioResult<()> {
        if self.entries.is_empty() {
            return Ok(());
        }

        let mut expected_prev = "genesis".to_string();

        for (i, entry) in self.entries.iter().enumerate() {
            // Sequence check
            if entry.sequence != i as u64 {
                return Err(DioError::Integrity(format!(
                    "Sequence gap at {}: expected {}, got {}",
                    i, i, entry.sequence
                )));
            }

            // Timestamp ordering (allow equal)
            if i > 0 && entry.timestamp < self.entries[i - 1].timestamp {
                return Err(DioError::Integrity(format!(
                    "Timestamp regression at sequence {}",
                    i
                )));
            }

            // Chain hash
            if entry.prev_hash != expected_prev {
                return Err(DioError::Integrity(format!(
                    "Chain hash mismatch at sequence {}",
                    i
                )));
            }
            expected_prev = entry.hash();
        }

        if expected_prev != self.chain_head {
            return Err(DioError::Integrity("Chain head mismatch".into()));
        }

        Ok(())
    }

    pub fn get_entries_by_type(&self, entry_type: EntryType) -> Vec<&TranscriptEntry> {
        self.entries.iter().filter(|e| e.entry_type == entry_type).collect()
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.execution_id.as_bytes());
        hasher.update(self.graph_hash.as_bytes());
        hasher.update(self.created_at.to_le_bytes());
        hasher.update(self.chain_head.as_bytes());
        if let Some(dh) = &self.determinism_hash {
            hasher.update(dh.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn sign(&mut self, key: &[u8]) {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("valid key");
        mac.update(self.hash().as_bytes());
        self.signature = Some(format!("{:x}", mac.finalize().into_bytes()));
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let Some(sig) = &self.signature else { return false };
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(key).expect("valid key");
        mac.update(self.hash().as_bytes());
        format!("{:x}", mac.finalize().into_bytes()) == *sig
    }
}

// =============================================================================
// EXECUTION CONTEXT
// =============================================================================

#[derive(Debug)]
pub struct ExecutionContext {
    pub execution_id: String,
    pub graph: ExecutionGraph,
    pub transcript: ExecutionTranscript,
    pub determinism_tracker: DeterminismTracker,
    pub start_time: u64,
    pub status: ExecutionStatus,
    pub error: Option<String>,
    node_results: HashMap<String, serde_json::Value>,
}

// =============================================================================
// POLICY ENGINE
// =============================================================================

#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn enforce_graph(&self, graph: &ExecutionGraph, transcript: &mut ExecutionTranscript) -> DioResult<()> {
        for rule in &self.rules {
            if let PolicyType::ResourceLimits = rule.policy_type {
                if let Some(max) = rule.conditions.get("max_nodes").and_then(|v| v.as_u64()) {
                    if graph.nodes.len() as u64 > max {
                        return self.violation(rule, transcript, format!(
                            "Graph has {} nodes, max is {}", graph.nodes.len(), max
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn enforce_node(&self, node: &GraphNode, transcript: &mut ExecutionTranscript) -> DioResult<()> {
        for rule in &self.rules {
            match rule.policy_type {
                PolicyType::ModelAccess if node.node_type == NodeType::ModelCall => {
                    if let (Some(model), Some(allowed)) = (
                        node.data.get("model_name").and_then(|v| v.as_str()),
                        rule.conditions.get("allowed_models").and_then(|v| v.as_array()),
                    ) {
                        if !allowed.iter().any(|v| v.as_str() == Some(model)) {
                            return self.violation(rule, transcript, format!(
                                "Model '{}' not allowed", model
                            ));
                        }
                    }
                }
                PolicyType::ToolAccess if node.node_type == NodeType::ToolCall => {
                    if let (Some(tool), Some(allowed)) = (
                        node.data.get("tool_name").and_then(|v| v.as_str()),
                        rule.conditions.get("allowed_tools").and_then(|v| v.as_array()),
                    ) {
                        if !allowed.iter().any(|v| v.as_str() == Some(tool)) {
                            return self.violation(rule, transcript, format!(
                                "Tool '{}' not allowed", tool
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn violation(
        &self,
        rule: &PolicyRule,
        transcript: &mut ExecutionTranscript,
        message: String,
    ) -> DioResult<()> {
        let mut data = HashMap::new();
        data.insert("policy_id".into(), serde_json::Value::String(rule.id.clone()));
        data.insert("policy_type".into(), serde_json::Value::String(rule.policy_type.to_string()));
        data.insert("message".into(), serde_json::Value::String(message.clone()));
        
        transcript.add_entry(EntryType::PolicyViolation, data);
        
        Err(DioError::PolicyViolation {
            message,
            policy_type: rule.policy_type,
            details: HashMap::new(),
        })
    }
}


// =============================================================================
// INTELLIGENCE ORCHESTRATOR - Thread-safe execution engine
// =============================================================================

/// Thread-safe orchestrator for deterministic intelligence execution.
pub struct IntelligenceOrchestrator {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    executions: Arc<RwLock<HashMap<String, ExecutionContext>>>,
    max_cached: usize,
}

impl IntelligenceOrchestrator {
    /// Create a new orchestrator with the given policy engine and cache limit.
    pub fn new(policy_engine: PolicyEngine, max_cached: usize) -> Self {
        Self {
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            executions: Arc::new(RwLock::new(HashMap::new())),
            max_cached,
        }
    }

    /// Submit an execution graph for processing. Returns execution ID.
    pub fn submit_graph(&self, graph: ExecutionGraph) -> DioResult<String> {
        graph.validate()?;

        let execution_id = uuid::Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let graph_hash = graph.hash();
        let mut transcript = ExecutionTranscript::new(
            execution_id.clone(),
            graph_hash.clone(),
            timestamp,
        );

        // Record submission
        let mut data = HashMap::new();
        data.insert("graph_hash".into(), serde_json::Value::String(graph_hash));
        transcript.add_entry(EntryType::Submission, data);

        let context = ExecutionContext {
            execution_id: execution_id.clone(),
            graph,
            transcript,
            determinism_tracker: DeterminismTracker::new(),
            start_time: timestamp,
            status: ExecutionStatus::Pending,
            error: None,
            node_results: HashMap::new(),
        };

        // Enforce cache limit with LRU-style eviction
        let mut executions = self.executions.write();
        if executions.len() >= self.max_cached {
            let to_remove: Option<String> = executions
                .iter()
                .filter(|(_, ctx)| {
                    ctx.status == ExecutionStatus::Completed
                        || ctx.status == ExecutionStatus::Failed
                })
                .min_by_key(|(_, ctx)| ctx.start_time)
                .map(|(id, _)| id.clone());

            if let Some(id) = to_remove {
                executions.remove(&id);
            }
        }

        executions.insert(execution_id.clone(), context);
        Ok(execution_id)
    }

    /// Execute a previously submitted graph. Returns the execution transcript.
    pub fn execute(&self, execution_id: &str) -> DioResult<ExecutionTranscript> {
        // Validate state transition
        {
            let executions = self.executions.read();
            let ctx = executions.get(execution_id).ok_or_else(|| {
                DioError::State(format!("Unknown execution ID: {}", execution_id))
            })?;
            if ctx.status != ExecutionStatus::Pending {
                return Err(DioError::State(format!(
                    "Execution {} is {:?}, expected Pending",
                    execution_id, ctx.status
                )));
            }
        }

        // Transition to Running
        {
            let mut executions = self.executions.write();
            if let Some(ctx) = executions.get_mut(execution_id) {
                ctx.status = ExecutionStatus::Running;
            }
        }

        // Enforce graph-level policies
        {
            let policy_engine = self.policy_engine.read();
            let mut executions = self.executions.write();
            let ctx = executions.get_mut(execution_id).unwrap();

            if let Err(e) = policy_engine.enforce_graph(&ctx.graph, &mut ctx.transcript) {
                ctx.status = ExecutionStatus::Failed;
                ctx.error = Some(e.to_string());

                let mut data = HashMap::new();
                data.insert("error".into(), serde_json::Value::String(e.to_string()));
                ctx.transcript.add_entry(EntryType::Failure, data);
                return Err(e);
            }
        }

        // Execute nodes in topological order
        if let Err(e) = self.execute_topologically(execution_id) {
            let mut executions = self.executions.write();
            if let Some(ctx) = executions.get_mut(execution_id) {
                ctx.status = ExecutionStatus::Failed;
                ctx.error = Some(e.to_string());
            }
            return Err(e);
        }

        // Finalize execution
        let mut executions = self.executions.write();
        let ctx = executions.get_mut(execution_id).unwrap();
        ctx.status = ExecutionStatus::Completed;

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            - ctx.start_time;

        let mut data = HashMap::new();
        data.insert("status".into(), serde_json::Value::String("completed".into()));
        data.insert("duration_seconds".into(), serde_json::Value::Number(duration.into()));
        ctx.transcript.add_entry(EntryType::Completion, data);

        // Persist determinism hash
        ctx.transcript.determinism_hash = Some(ctx.determinism_tracker.hash());

        Ok(ctx.transcript.clone())
    }

    fn execute_topologically(&self, execution_id: &str) -> DioResult<()> {
        let order = {
            let executions = self.executions.read();
            let ctx = executions.get(execution_id).unwrap();
            self.topological_order(&ctx.graph)?
        };

        for node_id in order {
            self.execute_node(execution_id, &node_id)?;
        }
        Ok(())
    }

    fn topological_order(&self, graph: &ExecutionGraph) -> DioResult<Vec<String>> {
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();

        for node in &graph.nodes {
            in_degree.insert(&node.id, node.dependencies.len());
            dependents.entry(&node.id).or_default();
            for dep in &node.dependencies {
                dependents.entry(dep.as_str()).or_default().push(&node.id);
            }
        }

        // Collect nodes with no dependencies, sort for determinism
        let mut ready: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&id, _)| id)
            .collect();
        ready.sort();

        let mut queue: VecDeque<&str> = ready.into_iter().collect();
        let mut order = Vec::new();

        while let Some(node_id) = queue.pop_front() {
            order.push(node_id.to_string());

            if let Some(deps) = dependents.get(node_id) {
                let mut next_ready = Vec::new();
                for &dep_id in deps {
                    if let Some(deg) = in_degree.get_mut(dep_id) {
                        *deg -= 1;
                        if *deg == 0 {
                            next_ready.push(dep_id);
                        }
                    }
                }
                // Sort for determinism
                next_ready.sort();
                queue.extend(next_ready);
            }
        }

        if order.len() != graph.nodes.len() {
            return Err(DioError::Graph("Circular dependency detected during execution".into()));
        }

        Ok(order)
    }

    fn execute_node(&self, execution_id: &str, node_id: &str) -> DioResult<()> {
        // Clone node data for execution
        let node = {
            let executions = self.executions.read();
            let ctx = executions.get(execution_id).unwrap();
            ctx.graph
                .get_node(node_id)
                .ok_or_else(|| DioError::Execution(format!("Node not found: {}", node_id)))?
                .clone()
        };

        // Record node start
        {
            let mut executions = self.executions.write();
            let ctx = executions.get_mut(execution_id).unwrap();

            let mut data = HashMap::new();
            data.insert("node_id".into(), serde_json::Value::String(node_id.into()));
            data.insert("node_type".into(), serde_json::Value::String(node.node_type.to_string()));
            data.insert("determinism".into(), serde_json::Value::String(node.determinism.to_string()));
            ctx.transcript.add_entry(EntryType::NodeStart, data);
        }

        // Enforce node policies
        {
            let policy_engine = self.policy_engine.read();
            let mut executions = self.executions.write();
            let ctx = executions.get_mut(execution_id).unwrap();

            if let Err(e) = policy_engine.enforce_node(&node, &mut ctx.transcript) {
                let mut data = HashMap::new();
                data.insert("node_id".into(), serde_json::Value::String(node_id.into()));
                data.insert("error".into(), serde_json::Value::String(e.to_string()));
                ctx.transcript.add_entry(EntryType::NodeFailure, data);
                return Err(e);
            }
        }

        // Simulate execution with deterministic input hash
        let result = self.simulate_node(&node);

        // Record completion
        {
            let mut executions = self.executions.write();
            let ctx = executions.get_mut(execution_id).unwrap();

            ctx.determinism_tracker.record(node_id.to_string(), node.determinism);
            ctx.node_results.insert(node_id.to_string(), result.clone());

            let mut data = HashMap::new();
            data.insert("node_id".into(), serde_json::Value::String(node_id.into()));
            data.insert("result".into(), result);
            data.insert("determinism".into(), serde_json::Value::String(node.determinism.to_string()));
            ctx.transcript.add_entry(EntryType::NodeComplete, data);
        }

        Ok(())
    }

    fn simulate_node(&self, node: &GraphNode) -> serde_json::Value {
        // Compute deterministic input hash
        let mut hasher = Sha256::new();
        hasher.update(node.id.as_bytes());
        hasher.update(node.node_type.to_string().as_bytes());

        let mut keys: Vec<_> = node.data.keys().collect();
        keys.sort();
        for k in keys {
            hasher.update(k.as_bytes());
            hasher.update(node.data[k].to_string().as_bytes());
        }

        let input_hash = format!("{:x}", hasher.finalize());

        serde_json::json!({
            "node_id": node.id,
            "status": "success",
            "input_hash": input_hash,
            "simulated": true
        })
    }

    /// Verify execution integrity: transcript chain, graph hash, determinism hash.
    pub fn verify(&self, execution_id: &str) -> DioResult<bool> {
        let executions = self.executions.read();
        let ctx = executions.get(execution_id).ok_or_else(|| {
            DioError::State(format!("Unknown execution ID: {}", execution_id))
        })?;

        // Verify transcript integrity
        ctx.transcript.verify_integrity()?;

        // Verify graph hash
        if ctx.graph.hash() != ctx.transcript.graph_hash {
            return Ok(false);
        }

        // Verify determinism hash
        if let Some(ref recorded) = ctx.transcript.determinism_hash {
            if ctx.determinism_tracker.hash() != *recorded {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get execution status.
    pub fn status(&self, execution_id: &str) -> Option<ExecutionStatus> {
        self.executions.read().get(execution_id).map(|c| c.status)
    }

    /// Get a copy of the transcript.
    pub fn transcript(&self, execution_id: &str) -> Option<ExecutionTranscript> {
        self.executions.read().get(execution_id).map(|c| c.transcript.clone())
    }

    /// Add a policy rule to the engine.
    pub fn add_policy(&self, rule: PolicyRule) {
        self.policy_engine.write().add_rule(rule);
    }
}

// =============================================================================
// UNIT TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, node_type: NodeType, deps: &[&str]) -> GraphNode {
        GraphNode::new(
            id.into(),
            node_type,
            HashMap::new(),
            Determinism::Deterministic,
            deps.iter().map(|s| s.to_string()).collect(),
            HashMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn test_graph_empty_rejected() {
        let result = ExecutionGraph::new(vec![], HashMap::new(), "1.0".into());
        assert!(matches!(result, Err(DioError::Graph(_))));
    }

    #[test]
    fn test_graph_duplicate_ids_rejected() {
        let n1 = node("a", NodeType::Output, &[]);
        let n2 = node("a", NodeType::Output, &[]);
        let result = ExecutionGraph::new(vec![n1, n2], HashMap::new(), "1.0".into());
        assert!(matches!(result, Err(DioError::Graph(_))));
    }

    #[test]
    fn test_graph_cycle_detected() {
        let n1 = node("a", NodeType::Output, &["b"]);
        let n2 = node("b", NodeType::Output, &["a"]);
        let g = ExecutionGraph::new(vec![n1, n2], HashMap::new(), "1.0".into()).unwrap();
        assert!(matches!(g.validate(), Err(DioError::Graph(_))));
    }

    #[test]
    fn test_graph_missing_dep_detected() {
        let n1 = node("a", NodeType::Output, &["missing"]);
        let g = ExecutionGraph::new(vec![n1], HashMap::new(), "1.0".into()).unwrap();
        assert!(matches!(g.validate(), Err(DioError::Graph(_))));
    }

    #[test]
    fn test_graph_hash_determinism() {
        let n1 = node("a", NodeType::Output, &[]);
        let n2 = node("b", NodeType::ModelCall, &["a"]);

        let g1 = ExecutionGraph::new(vec![n1.clone(), n2.clone()], HashMap::new(), "1.0".into()).unwrap();
        let g2 = ExecutionGraph::new(vec![n2, n1], HashMap::new(), "1.0".into()).unwrap();

        assert_eq!(g1.hash(), g2.hash(), "Hash must be order-independent");
    }

    #[test]
    fn test_determinism_tracker_hash_determinism() {
        let mut t1 = DeterminismTracker::new();
        t1.record("b".into(), Determinism::Deterministic);
        t1.record("a".into(), Determinism::Deterministic);

        let mut t2 = DeterminismTracker::new();
        t2.record("a".into(), Determinism::Deterministic);
        t2.record("b".into(), Determinism::Deterministic);

        assert_eq!(t1.hash(), t2.hash(), "Hash must be order-independent");
    }

    #[test]
    fn test_transcript_chain_integrity() {
        let mut t = ExecutionTranscript::new("test".into(), "hash".into(), 1000);
        t.add_entry(EntryType::Submission, HashMap::new());
        t.add_entry(EntryType::Completion, HashMap::new());
        assert!(t.verify_integrity().is_ok());
    }

    #[test]
    fn test_transcript_signing() {
        let mut t = ExecutionTranscript::new("test".into(), "hash".into(), 1000);
        t.add_entry(EntryType::Submission, HashMap::new());

        let key = b"secret_key_32_bytes_exactly!!!!";
        t.sign(key);
        assert!(t.verify_signature(key));
        assert!(!t.verify_signature(b"wrong_key_32_bytes_exactly!!!!!"));
    }

    #[test]
    fn test_policy_model_access_enforcement() {
        let mut conditions = HashMap::new();
        conditions.insert(
            "allowed_models".into(),
            serde_json::json!(["gpt-4", "claude-3"]),
        );

        let rule = PolicyRule::new(
            "model_policy".into(),
            PolicyType::ModelAccess,
            conditions,
            vec!["allow".into()],
            "Test policy".into(),
        )
        .unwrap();

        let mut engine = PolicyEngine::new();
        engine.add_rule(rule);

        // Allowed model
        let mut data = HashMap::new();
        data.insert("model_name".into(), serde_json::json!("gpt-4"));
        let allowed_node = GraphNode::new(
            "n1".into(),
            NodeType::ModelCall,
            data,
            Determinism::Deterministic,
            vec![],
            HashMap::new(),
        )
        .unwrap();

        let mut transcript = ExecutionTranscript::new("t".into(), "h".into(), 0);
        assert!(engine.enforce_node(&allowed_node, &mut transcript).is_ok());

        // Disallowed model
        let mut data2 = HashMap::new();
        data2.insert("model_name".into(), serde_json::json!("llama-2"));
        let disallowed_node = GraphNode::new(
            "n2".into(),
            NodeType::ModelCall,
            data2,
            Determinism::Deterministic,
            vec![],
            HashMap::new(),
        )
        .unwrap();

        let result = engine.enforce_node(&disallowed_node, &mut transcript);
        assert!(matches!(result, Err(DioError::PolicyViolation { .. })));
    }

    #[test]
    fn test_orchestrator_full_lifecycle() {
        let engine = PolicyEngine::new();
        let orchestrator = IntelligenceOrchestrator::new(engine, 100);

        let n1 = node("input", NodeType::Output, &[]);
        let n2 = node("process", NodeType::ModelCall, &["input"]);
        let n3 = node("output", NodeType::Output, &["process"]);

        let graph = ExecutionGraph::new(
            vec![n1, n2, n3],
            HashMap::new(),
            "1.0".into(),
        )
        .unwrap();

        let exec_id = orchestrator.submit_graph(graph).unwrap();
        assert_eq!(orchestrator.status(&exec_id), Some(ExecutionStatus::Pending));

        let transcript = orchestrator.execute(&exec_id).unwrap();
        assert_eq!(orchestrator.status(&exec_id), Some(ExecutionStatus::Completed));

        // Verify integrity
        assert!(orchestrator.verify(&exec_id).unwrap());
        assert!(transcript.verify_integrity().is_ok());
        assert!(transcript.determinism_hash.is_some());

        // Check all nodes were executed
        let completions = transcript.get_entries_by_type(EntryType::NodeComplete);
        assert_eq!(completions.len(), 3);
    }

    #[test]
    fn test_orchestrator_policy_blocks_execution() {
        let mut engine = PolicyEngine::new();

        let mut conditions = HashMap::new();
        conditions.insert("allowed_models".into(), serde_json::json!(["allowed-model"]));
        engine.add_rule(
            PolicyRule::new(
                "strict".into(),
                PolicyType::ModelAccess,
                conditions,
                vec!["allow".into()],
                "Strict model policy".into(),
            )
            .unwrap(),
        );

        let orchestrator = IntelligenceOrchestrator::new(engine, 100);

        let mut data = HashMap::new();
        data.insert("model_name".into(), serde_json::json!("forbidden-model"));

        let n = GraphNode::new(
            "bad_node".into(),
            NodeType::ModelCall,
            data,
            Determinism::Deterministic,
            vec![],
            HashMap::new(),
        )
        .unwrap();

        let graph = ExecutionGraph::new(vec![n], HashMap::new(), "1.0".into()).unwrap();
        let exec_id = orchestrator.submit_graph(graph).unwrap();

        let result = orchestrator.execute(&exec_id);
        assert!(matches!(result, Err(DioError::PolicyViolation { .. })));
        assert_eq!(orchestrator.status(&exec_id), Some(ExecutionStatus::Failed));
    }

    #[test]
    fn test_node_id_validation() {
        // Valid IDs
        assert!(GraphNode::new("valid_id".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_ok());
        assert!(GraphNode::new("valid-id".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_ok());
        assert!(GraphNode::new("ValidId123".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_ok());

        // Invalid: empty
        assert!(GraphNode::new("".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_err());

        // Invalid: special characters
        assert!(GraphNode::new("invalid id".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_err());
        assert!(GraphNode::new("invalid/id".into(), NodeType::Output, HashMap::new(), Determinism::Deterministic, vec![], HashMap::new()).is_err());
    }
}
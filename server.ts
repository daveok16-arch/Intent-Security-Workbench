/**
 * Backend Server & Real-time WebSocket Server for Intent Security Workbench
 * Phase 0 Foundational Architecture
 * 
 * Strict Phase 0 Rule:
 * Never claim an engine executed, a vulnerability was verified, or a proof was generated
 * unless the underlying operation actually took place.
 */

import express from 'express';
import http from 'http';
import path from 'path';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer as createViteServer } from 'vite';

import { globalDB } from './apps/api/db_store.js';
import { globalJobOrchestrator } from './packages/orchestrator/src/index.js';
import { globalEngineRegistry } from './engines/engine_registry.js';
import { KNOWN_TAXONOMY } from './packages/vulnerability-intelligence/src/index.js';
import { SandboxSecurityEnforcer, DEFAULT_SANDBOX_POLICY } from './sandbox/sandbox_boundary.js';
import { getProgramAdapter } from './adapters/programs/index.js';
import { getTargetAdapter } from './adapters/targets/index.js';
import { verifyArtifactIntegrity } from './packages/evidence/src/index.js';
import { ScopeAssetType, ScopeInclusionStatus } from './packages/core/src/index.js';
import {
  globalCandidateStore,
  globalSecurityRuleRegistry,
  executeStaticAnalysisPipeline,
} from './packages/static-analysis/src/index.js';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Create HTTP server
const server = http.createServer(app);

// WebSocket Server attached for real-time telemetry
const wss = new WebSocketServer({ server, path: '/ws' });
const connectedClients = new Set<WebSocket>();

wss.on('connection', (ws) => {
  connectedClients.add(ws);
  
  // Send immediate welcome handshake with current system state
  ws.send(JSON.stringify({
    type: 'system_connected',
    timestamp: new Date().toISOString(),
    message: 'Connected to Intent Security Workbench Live Event Stream',
  }));

  ws.on('close', () => {
    connectedClients.delete(ws);
  });

  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg.toString());
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: new Date().toISOString() }));
      }
    } catch {
      // Ignore malformed client message
    }
  });
});

function broadcastEvent(type: string, payload: any) {
  const message = JSON.stringify({
    type,
    payload,
    timestamp: new Date().toISOString(),
  });
  for (const client of connectedClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  }
}

// Hook Orchestrator events to WebSocket broadcast
globalJobOrchestrator.subscribe((event) => {
  broadcastEvent(event.type, {
    job: event.job,
    timestamp: event.timestamp,
  });
});

// =============================================================
// REST API ROUTES
// =============================================================

// System Health & Telemetry
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'intent-security-workbench',
    phase: 0,
    active_websockets: connectedClients.size,
  });
});

app.get('/api/readiness', async (req, res) => {
  const engineStatuses = await globalEngineRegistry.checkAllAvailability();
  res.json({
    status: 'ready',
    database: 'connected',
    job_worker: 'active',
    websocket: 'operational',
    anti_fabrication_mode: 'enforced',
    registered_engines: engineStatuses.length,
    active_jobs: globalJobOrchestrator.listJobs({ status: 'RUNNING' as any }).length,
  });
});

app.get('/api/version', (req, res) => {
  res.json({
    api_version: '0.1.0-phase0',
    capabilities: [
      'MODULAR_PROGRAM_ADAPTERS',
      'MODULAR_TARGET_ADAPTERS',
      'EVIDENCE_SHA256_PROVENANCE',
      'FINDING_STATE_MACHINE',
      'REAL_TIME_WEBSOCKET_ORCHESTRATOR',
      'SANDBOX_SECURITY_BOUNDARY',
    ],
    phase_0_constraint: 'Foundational architecture only. No simulated findings or mock scanners.',
  });
});

// System Status Overview
app.get('/api/system/status', async (req, res) => {
  const engines = await globalEngineRegistry.check_all();
  const jobs = globalJobOrchestrator.listJobs();
  res.json({
    programs_count: globalDB.listPrograms().length,
    targets_count: globalDB.listTargets().length,
    investigations_count: globalDB.listInvestigations().length,
    evidence_count: globalDB.listEvidence().length,
    findings_count: globalDB.listFindings().length,
    jobs_count: jobs.length,
    jobs_queued: jobs.filter(j => j.status === 'QUEUED').length,
    jobs_running: jobs.filter(j => j.status === 'RUNNING').length,
    jobs_completed: jobs.filter(j => j.status === 'COMPLETED').length,
    jobs_failed: jobs.filter(j => j.status === 'FAILED').length,
    engines_total: engines.length,
    engines_available: engines.filter(e => e.status === 'AVAILABLE' || (e as any).available === true).length,
    engines_unavailable: engines.filter(e => e.status !== 'AVAILABLE' && (e as any).available !== true).length,
    connected_websockets: connectedClients.size,
  });
});

// -------------------------------------------------------------
// Programs & Program Scope Endpoints (Phase 1)
// -------------------------------------------------------------
app.get(['/api/v1/programs', '/api/programs'], (req, res) => {
  res.json(globalDB.listPrograms());
});

app.get(['/api/v1/programs/adapters', '/api/programs/adapters'], (req, res) => {
  const adapters = [
    {
      platform: 'IMMUNEFI',
      name: 'Immunefi Program Adapter',
      live_fetch_supported: false,
      capabilities: ['SCHEMA_VALIDATION', 'SCOPE_NORMALIZATION', 'POLICY_NORMALIZATION'],
      description: 'Web3 & Smart Contract Bug Bounty Platform. Authoritative rules of engagement.',
    },
    {
      platform: 'HACKENPROOF',
      name: 'HackenProof Program Adapter',
      live_fetch_supported: false,
      capabilities: ['SCHEMA_VALIDATION', 'SCOPE_NORMALIZATION', 'POLICY_NORMALIZATION'],
      description: 'Web3 and Blockchain vulnerability coordination and responsible disclosure.',
    },
    {
      platform: 'CANTINA',
      name: 'Cantina Program Adapter',
      live_fetch_supported: false,
      capabilities: ['SCHEMA_VALIDATION', 'SCOPE_NORMALIZATION', 'POLICY_NORMALIZATION'],
      description: 'Competitive audits and decentralized security reviews.',
    },
    {
      platform: 'HACKERONE',
      name: 'HackerOne Program Adapter',
      live_fetch_supported: false,
      capabilities: ['SCHEMA_VALIDATION', 'SCOPE_NORMALIZATION', 'POLICY_NORMALIZATION'],
      description: 'Enterprise bug bounty and coordinated vulnerability disclosure platform.',
    },
    {
      platform: 'CUSTOM',
      name: 'Custom / Private Program Adapter',
      live_fetch_supported: false,
      capabilities: ['SCHEMA_VALIDATION', 'SCOPE_NORMALIZATION', 'POLICY_NORMALIZATION'],
      description: 'Private engagement and authorized direct researcher agreement.',
    },
  ];
  res.json(adapters);
});

app.get(['/api/v1/programs/:id', '/api/programs/:id'], (req, res) => {
  const program = globalDB.getProgram(req.params.id);
  if (!program) return res.status(404).json({ error: 'Program not found.' });
  const scopeEntries = globalDB.listScopeEntries(req.params.id);
  res.json({ ...program, scope_entries: scopeEntries });
});

app.post(['/api/v1/programs', '/api/programs'], (req, res) => {
  try {
    const {
      name,
      platform,
      external_id,
      external_identifier,
      program_url,
      organization,
      description,
      status,
      policy_version,
      scope,
      exclusions,
      testing_rules,
      disclosure_rules,
      bounty_rules,
      bounty_policy,
      disclosure_policy,
      technology,
      freshness_status,
      source_reference,
      source_hash,
      metadata,
    } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Program name is required.' });
    }

    const adapter = getProgramAdapter(platform);
    const validation = adapter.validateProgram({ name, scope, program_url, external_id });
    if (!validation.valid) {
      return res.status(400).json({ error: 'Validation failed', details: validation.errors });
    }

    const program = globalDB.createProgram({
      name,
      platform,
      external_id: external_id || external_identifier,
      external_identifier: external_identifier || external_id,
      program_url,
      organization,
      description,
      status,
      policy_version,
      scope: scope || [],
      exclusions: adapter.extractExclusions(exclusions || []),
      testing_rules: testing_rules || [],
      disclosure_rules: disclosure_rules || [],
      bounty_rules,
      bounty_policy: adapter.normalizePolicy(bounty_policy || bounty_rules || ''),
      disclosure_policy,
      technology: technology || [],
      freshness_status,
      source_reference,
      source_hash,
      metadata,
    });

    broadcastEvent('program_created', program);
    res.status(201).json(program);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.patch(['/api/v1/programs/:id', '/api/programs/:id'], (req, res) => {
  try {
    const updated = globalDB.updateProgram(req.params.id, req.body);
    broadcastEvent('program_updated', updated);
    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete(['/api/v1/programs/:id', '/api/programs/:id'], (req, res) => {
  const success = globalDB.deleteProgram(req.params.id);
  if (!success) return res.status(404).json({ error: 'Program not found.' });
  broadcastEvent('program_deleted', { id: req.params.id });
  res.json({ success: true });
});

// Scope within Program
app.get(['/api/v1/programs/:id/scope', '/api/programs/:id/scope'], (req, res) => {
  const program = globalDB.getProgram(req.params.id);
  if (!program) return res.status(404).json({ error: 'Program not found.' });
  res.json(globalDB.listScopeEntries(req.params.id));
});

app.post(['/api/v1/programs/:id/scope', '/api/programs/:id/scope'], (req, res) => {
  try {
    const program = globalDB.getProgram(req.params.id);
    if (!program) return res.status(404).json({ error: 'Program not found.' });

    const { asset_type, asset_identifier, inclusion_status, environment, technology, source_reference, restrictions, notes, effective_from, effective_to, metadata } = req.body;
    if (!asset_identifier) {
      return res.status(400).json({ error: 'asset_identifier is required.' });
    }

    const entry = globalDB.createScopeEntry({
      program_id: req.params.id,
      asset_type,
      asset_identifier,
      inclusion_status,
      environment,
      technology,
      source_reference,
      restrictions,
      notes,
      effective_from,
      effective_to,
      metadata,
    });

    broadcastEvent('scope_entry_created', entry);
    res.status(201).json(entry);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post(['/api/v1/programs/:id/scope/import', '/api/programs/:id/scope/import'], (req, res) => {
  try {
    const { scope, replace_existing } = req.body;
    if (!Array.isArray(scope)) {
      return res.status(400).json({ error: 'scope array is required for import.' });
    }

    const imported = globalDB.importScope(req.params.id, scope, Boolean(replace_existing));
    broadcastEvent('scope_imported', { program_id: req.params.id, count: imported.length });
    res.status(201).json({ count: imported.length, scope_entries: imported });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Direct Scope Endpoints
// -------------------------------------------------------------
app.get(['/api/v1/scope', '/api/scope'], (req, res) => {
  const program_id = req.query.program_id as string | undefined;
  res.json(globalDB.listScopeEntries(program_id));
});

app.post(['/api/v1/scope', '/api/scope'], (req, res) => {
  try {
    const { program_id, pattern, asset_identifier, asset_type, inclusion_status, description, notes, restrictions } = req.body;
    const identifier = asset_identifier || pattern;
    if (!program_id || !identifier) {
      return res.status(400).json({ error: 'program_id and pattern (or asset_identifier) are required.' });
    }
    const entry = globalDB.createScopeEntry({
      program_id,
      asset_identifier: identifier,
      asset_type: asset_type || ScopeAssetType.REPOSITORY,
      inclusion_status: inclusion_status || ScopeInclusionStatus.IN_SCOPE,
      notes: notes || description || '',
      restrictions: restrictions || [],
    });
    broadcastEvent('scope_entry_created', entry);
    res.status(201).json(entry);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.get(['/api/v1/scope/:id', '/api/scope/:id'], (req, res) => {
  const entry = globalDB.getScopeEntry(req.params.id);
  if (!entry) return res.status(404).json({ error: 'Scope entry not found.' });
  res.json(entry);
});

app.delete(['/api/v1/scope/:id', '/api/scope/:id'], (req, res) => {
  const success = globalDB.deleteScopeEntry(req.params.id);
  if (!success) return res.status(404).json({ error: 'Scope entry not found.' });
  broadcastEvent('scope_entry_deleted', { id: req.params.id });
  res.json({ success: true });
});

// -------------------------------------------------------------
// Targets Endpoints (Phase 1)
// -------------------------------------------------------------
app.get(['/api/v1/targets', '/api/targets'], (req, res) => {
  const program_id = req.query.program_id as string | undefined;
  res.json(globalDB.listTargets(program_id));
});

app.get(['/api/v1/targets/:id', '/api/targets/:id'], (req, res) => {
  const target = globalDB.getTarget(req.params.id);
  if (!target) return res.status(404).json({ error: 'Target not found.' });
  const snapshots = globalDB.listSourceSnapshots(req.params.id);
  res.json({ ...target, source_snapshots: snapshots });
});

app.post(['/api/v1/targets', '/api/targets'], (req, res) => {
  try {
    const {
      program_id,
      name,
      target_type,
      ecosystem,
      identifier,
      repository_url,
      commit_hash,
      branch,
      deployment,
      deployment_information,
      chain,
      contract_address,
      source_hash,
      source_acquisition_status,
      authorization_status,
      scope_status,
      metadata,
    } = req.body;

    if (!program_id || !name) {
      return res.status(400).json({ error: 'program_id and name are required.' });
    }
    const program = globalDB.getProgram(program_id);
    if (!program) {
      return res.status(404).json({ error: `Associated program ${program_id} not found.` });
    }

    const adapter = getTargetAdapter(ecosystem);
    const validation = adapter.validateTarget({ name, target_type, deployment_information: deployment_information || deployment, repository_url });
    if (!validation.valid) {
      return res.status(400).json({ error: 'Validation failed', details: validation.errors });
    }

    const target = globalDB.createTarget({
      program_id,
      name,
      target_type,
      ecosystem,
      identifier: identifier || repository_url || contract_address || name,
      repository_url,
      commit_hash,
      branch,
      deployment: deployment || deployment_information,
      deployment_information: deployment_information || deployment,
      chain,
      contract_address,
      source_hash,
      source_acquisition_status,
      authorization_status,
      scope_status,
      metadata,
    });

    // Auto-evaluate scope upon creation
    const scopeDecision = globalDB.evaluateTargetScope(target.id);

    broadcastEvent('target_created', { ...target, scope_decision: scopeDecision });
    res.status(201).json(globalDB.getTarget(target.id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.patch(['/api/v1/targets/:id', '/api/targets/:id'], (req, res) => {
  try {
    const updated = globalDB.updateTarget(req.params.id, req.body);
    broadcastEvent('target_updated', updated);
    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/v1/targets/:id/scope/evaluate', '/api/targets/:id/scope/evaluate', '/api/targets/:id/evaluate-scope'], (req, res) => {
  try {
    const { investigation_request_id } = req.body || {};
    const result = globalDB.evaluateTargetScope(req.params.id, investigation_request_id);
    const target = globalDB.getTarget(req.params.id);
    broadcastEvent('scope_evaluated', { target, evaluation: result });
    res.json({ target, evaluation: result });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post(['/api/v1/targets/:id/source/acquire', '/api/targets/:id/source/acquire', '/api/targets/:id/acquire-source'], async (req, res) => {
  try {
    const { branch, commit, timeout_ms, investigation_id } = req.body || {};
    const result = await globalDB.acquireTargetSource(req.params.id, {
      branch,
      commit,
      timeout_ms,
      investigation_id,
    });

    const target = globalDB.getTarget(req.params.id);
    broadcastEvent('source_acquired', { target, result });
    res.json({ target, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get(['/api/v1/targets/:id/source/verify', '/api/targets/:id/source/verify'], async (req, res) => {
  try {
    const result = await globalDB.verifyTargetSourceIntegrity(req.params.id);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get(['/api/v1/targets/:id/source', '/api/targets/:id/source'], (req, res) => {
  const target = globalDB.getTarget(req.params.id);
  if (!target) return res.status(404).json({ error: 'Target not found.' });
  const snapshots = globalDB.listSourceSnapshots(req.params.id);
  res.json({
    target_id: target.id,
    source_acquisition_status: target.source_acquisition_status,
    source_hash: target.source_hash,
    commit_hash: target.commit_hash,
    branch: target.branch,
    repository_url: target.repository_url,
    snapshots_count: snapshots.length,
    snapshots,
  });
});

app.get(['/api/v1/targets/:id/authorization', '/api/targets/:id/authorization'], (req, res) => {
  const target = globalDB.getTarget(req.params.id);
  if (!target) return res.status(404).json({ error: 'Target not found.' });
  const program = globalDB.getProgram(target.program_id);
  res.json({
    target_id: target.id,
    target_name: target.name,
    program_id: target.program_id,
    program_name: program?.name || '',
    program_status: program?.status || 'UNKNOWN',
    scope_status: target.scope_status,
    authorization_status: target.authorization_status,
    is_authorized: target.authorization_status === 'AUTHORIZED',
    evaluated: target.scope_status !== 'NOT_EVALUATED',
  });
});

app.get(['/api/v1/source/snapshots', '/api/source/snapshots'], (req, res) => {
  const target_id = req.query.target_id as string | undefined;
  res.json(globalDB.listSourceSnapshots(target_id));
});

app.get(['/api/v1/source/snapshots/:id', '/api/source/snapshots/:id'], (req, res) => {
  const snap = globalDB.getSourceSnapshot(req.params.id);
  if (!snap) return res.status(404).json({ error: 'Source snapshot not found.' });
  res.json(snap);
});

app.patch('/api/targets/:id/source-status', (req, res) => {
  try {
    const { status, source_hash } = req.body;
    const target = globalDB.updateTargetSourceStatus(req.params.id, status, source_hash);
    broadcastEvent('target_updated', target);
    res.json(target);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete(['/api/v1/targets/:id', '/api/targets/:id'], (req, res) => {
  const success = globalDB.deleteTarget(req.params.id);
  if (!success) return res.status(404).json({ error: 'Target not found.' });
  broadcastEvent('target_deleted', { id: req.params.id });
  res.json({ success: true });
});

// -------------------------------------------------------------
// Investigation Pre-Flight Gate Endpoints (Phase 1)
// -------------------------------------------------------------
app.get(['/api/v1/investigations/:id/gate', '/api/investigations/:id/gate'], (req, res) => {
  try {
    const requireSource = req.query.require_source !== 'false';
    const strictFreshness = req.query.strict_freshness !== 'false';
    const result = globalDB.evaluateInvestigationGate(req.params.id, {
      requireSourceAcquisition: requireSource,
      strictFreshness,
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post(['/api/v1/investigations/:id/gate/evaluate', '/api/investigations/:id/gate/evaluate'], (req, res) => {
  try {
    const { require_source, strict_freshness } = req.body || {};
    const result = globalDB.evaluateInvestigationGate(req.params.id, {
      requireSourceAcquisition: require_source ?? true,
      strictFreshness: strict_freshness ?? true,
    });
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Investigations Endpoints
// -------------------------------------------------------------
app.get('/api/investigations', (req, res) => {
  const program_id = req.query.program_id as string | undefined;
  const target_id = req.query.target_id as string | undefined;
  res.json(globalDB.listInvestigations({ program_id, target_id }));
});

app.post('/api/investigations', (req, res) => {
  try {
    const { program_id, target_id, title, description } = req.body;
    if (!program_id || !target_id || !title) {
      return res.status(400).json({ error: 'program_id, target_id, and title are required.' });
    }

    const investigation = globalDB.createInvestigation({
      program_id,
      target_id,
      title,
      description,
    });

    broadcastEvent('investigation_created', investigation);
    res.status(201).json(investigation);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/investigations/:id/status', (req, res) => {
  try {
    const { status } = req.body;
    const inv = globalDB.updateInvestigationStatus(req.params.id, status);
    broadcastEvent('investigation_status_changed', inv);
    res.json(inv);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/investigations/:id', (req, res) => {
  const success = globalDB.deleteInvestigation(req.params.id);
  if (!success) return res.status(404).json({ error: 'Investigation not found.' });
  broadcastEvent('investigation_deleted', { id: req.params.id });
  res.json({ success: true });
});

// -------------------------------------------------------------
// Jobs Orchestration Endpoints
// -------------------------------------------------------------
app.get('/api/jobs', (req, res) => {
  const investigation_id = req.query.investigation_id as string | undefined;
  const status = req.query.status as any;
  res.json(globalJobOrchestrator.listJobs({ investigation_id, status }));
});

app.get('/api/jobs/:id', (req, res) => {
  const job = globalJobOrchestrator.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found.' });
  res.json(job);
});

app.get('/api/jobs/:id/logs', (req, res) => {
  res.json(globalJobOrchestrator.getLogs(req.params.id));
});

app.post('/api/jobs', (req, res) => {
  try {
    const { investigation_id, target_id, engine, operation, metadata } = req.body;
    if (!investigation_id || !target_id || !engine || !operation) {
      return res.status(400).json({ error: 'investigation_id, target_id, engine, and operation are required.' });
    }

    const job = globalJobOrchestrator.createJob({
      id: `job-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      investigation_id,
      target_id,
      engine,
      operation,
      metadata,
    });

    res.status(201).json(job);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/run', async (req, res) => {
  try {
    const jobId = req.params.id;
    // Execute asynchronously on background worker
    setTimeout(async () => {
      await globalJobOrchestrator.runJob(jobId, (artifact) => {
        globalDB.evidence.set(artifact.id, artifact);
        globalDB.rawArtifactStorage.set(artifact.id, artifact.content_preview || '');
        broadcastEvent('evidence_created', artifact);
      });
    }, 100);

    res.json({ message: 'Job execution dispatched to worker.', job_id: jobId, status: 'RUNNING' });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/jobs/:id/cancel', async (req, res) => {
  try {
    const job = await globalJobOrchestrator.cancelJob(req.params.id);
    res.json(job);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Evidence Locker Endpoints (Phase 0.2)
// -------------------------------------------------------------
app.get(['/api/v1/investigations/:id/evidence', '/api/investigations/:id/evidence'], (req, res) => {
  res.json(globalDB.listEvidence(req.params.id));
});

app.get('/api/evidence', (req, res) => {
  const investigation_id = req.query.investigation_id as string | undefined;
  res.json(globalDB.listEvidence(investigation_id));
});

app.get(['/api/v1/evidence/:id', '/api/evidence/:id'], (req, res) => {
  const artifact = globalDB.getEvidenceArtifact(req.params.id);
  if (!artifact) return res.status(404).json({ error: 'Evidence artifact not found.' });
  res.json(artifact);
});

app.get(['/api/v1/evidence/:id/integrity', '/api/evidence/:id/integrity', '/api/evidence/:id/verify'], async (req, res) => {
  const artifact = globalDB.getEvidenceArtifact(req.params.id);
  if (!artifact) return res.status(404).json({ error: 'Evidence artifact not found.' });

  const integrity = await globalDB.verifyArtifactIntegrity(req.params.id);
  res.json({
    artifact_id: artifact.id,
    producer: artifact.producer,
    producer_version: artifact.producer_version,
    command: artifact.command,
    expected_sha256: artifact.sha256,
    actual_sha256: integrity.actual_sha256,
    size_bytes: integrity.size_bytes,
    status: integrity.status,
    valid: integrity.valid,
    error: integrity.error,
  });
});

app.get('/api/evidence/:id/download', async (req, res) => {
  const artifact = globalDB.getEvidenceArtifact(req.params.id);
  if (!artifact) return res.status(404).json({ error: 'Evidence artifact not found.' });

  try {
    let raw = globalDB.getRawArtifactContent(req.params.id);
    if (raw === undefined && artifact.path && await globalDB.storage.exists(artifact.path)) {
      raw = await globalDB.storage.read(artifact.path);
    }
    res.setHeader('Content-Type', artifact.mime_type || 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="${artifact.id}.txt"`);
    res.send(raw || '');
  } catch (err: any) {
    res.status(500).json({ error: `Failed to read artifact: ${err.message}` });
  }
});

app.post(['/api/v1/evidence', '/api/evidence'], (req, res) => {
  try {
    const { investigation_id, target_id, artifact_type, producer, producer_version, command, working_directory, source_snapshot_id, target_hash, content, path_or_reference, path: customPath, mime_type, metadata } = req.body;
    if (!investigation_id || !artifact_type || !producer || content === undefined) {
      return res.status(400).json({ error: 'investigation_id, artifact_type, producer, and content are required.' });
    }

    const artifact = globalDB.storeEvidenceArtifact({
      investigation_id,
      target_id,
      artifact_type,
      producer,
      producer_version: producer_version || '1.0.0',
      command: command || '',
      working_directory,
      source_snapshot_id,
      target_hash,
      content,
      path: customPath || path_or_reference,
      mime_type,
      metadata,
    });

    broadcastEvent('evidence_created', artifact);
    res.status(201).json(artifact);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Provenance Graph & Events Endpoints (Phase 0.2)
// -------------------------------------------------------------
app.get(['/api/v1/investigations/:id/provenance', '/api/investigations/:id/provenance'], (req, res) => {
  try {
    const jobs = globalJobOrchestrator.listJobs({ investigation_id: req.params.id });
    const graph = globalDB.getInvestigationProvenance(req.params.id, jobs);
    res.json(graph);
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

app.get(['/api/v1/findings/:id/provenance', '/api/findings/:id/provenance'], (req, res) => {
  try {
    const finding = globalDB.getFinding(req.params.id);
    if (!finding) return res.status(404).json({ error: 'Finding not found.' });
    const jobs = globalJobOrchestrator.listJobs({ investigation_id: finding.investigation_id });
    const chain = globalDB.getFindingProvenance(req.params.id, jobs);
    res.json(chain);
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

app.get(['/api/v1/investigations/:id/events', '/api/investigations/:id/events'], (req, res) => {
  res.json(globalDB.listEvidenceEvents(req.params.id));
});

app.post(['/api/v1/investigations/:id/events', '/api/investigations/:id/events'], (req, res) => {
  try {
    const { event_type, actor, producer, producer_version, input_artifacts, output_artifacts, metadata } = req.body;
    if (!event_type || !producer) {
      return res.status(400).json({ error: 'event_type and producer are required.' });
    }

    const event = globalDB.recordEvidenceEvent({
      investigation_id: req.params.id,
      event_type,
      actor,
      producer,
      producer_version,
      input_artifacts,
      output_artifacts,
      metadata,
    });

    broadcastEvent('evidence_event_recorded', event);
    res.status(201).json(event);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Source Snapshots
app.get('/api/v1/snapshots', (req, res) => {
  const target_id = req.query.target_id as string | undefined;
  res.json(globalDB.listSourceSnapshots(target_id));
});

app.get('/api/v1/snapshots/:id', (req, res) => {
  const snap = globalDB.getSourceSnapshot(req.params.id);
  if (!snap) return res.status(404).json({ error: 'Snapshot not found.' });
  res.json(snap);
});

app.post('/api/v1/snapshots', async (req, res) => {
  try {
    const { target_id, investigation_id, repository_url, commit_hash, branch, acquisition_method, content, filename, metadata } = req.body;
    if (!target_id || !acquisition_method) {
      return res.status(400).json({ error: 'target_id and acquisition_method are required.' });
    }

    const snap = globalDB.createSourceSnapshot({
      target_id,
      investigation_id,
      repository_url,
      commit_hash,
      branch,
      acquisition_method,
      metadata,
    });

    if (content) {
      await globalDB.acquireSourceSnapshotContent(snap.id, content, filename);
    }

    res.status(201).json(snap);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Findings State Machine Endpoints
// -------------------------------------------------------------
app.get('/api/findings', (req, res) => {
  const investigation_id = req.query.investigation_id as string | undefined;
  res.json(globalDB.listFindings(investigation_id));
});

app.post('/api/findings', (req, res) => {
  try {
    const { investigation_id, target_id, title, category, severity, confidence, evidence_artifact_ids, reproduction_steps, mitigation_notes, metadata } = req.body;
    if (!investigation_id || !target_id || !title || !category || !severity) {
      return res.status(400).json({ error: 'investigation_id, target_id, title, category, and severity are required.' });
    }

    const finding = globalDB.createFinding({
      investigation_id,
      target_id,
      title,
      category,
      severity,
      confidence,
      evidence_artifact_ids,
      reproduction_steps,
      mitigation_notes,
      metadata,
    });

    broadcastEvent('finding_created', finding);
    res.status(201).json(finding);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/findings/:id/transition', (req, res) => {
  try {
    const { target_status, reason, actor } = req.body;
    if (!target_status || !reason) {
      return res.status(400).json({ error: 'target_status and reason are required.' });
    }

    const finding = globalDB.transitionFinding(req.params.id, target_status, reason, actor || 'security-researcher');
    broadcastEvent('finding_updated', finding);
    res.json(finding);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/findings/:id/link-evidence', (req, res) => {
  try {
    const { evidence_id } = req.body;
    if (!evidence_id) return res.status(400).json({ error: 'evidence_id is required.' });

    const finding = globalDB.linkEvidenceToFinding(req.params.id, evidence_id);
    broadcastEvent('finding_updated', finding);
    res.json(finding);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Engine Registry & Taxonomy Endpoints (Phase 0.1)
// -------------------------------------------------------------

// GET /api/v1/engines - List all engines with live availability verification
app.get(['/api/v1/engines', '/api/engines'], async (req, res) => {
  const engines = globalEngineRegistry.list();
  const availability = await globalEngineRegistry.check_all();
  
  const results = engines.map(engine => {
    const avail = availability.find(a => a.engine_id === engine.engine_id) || {
      engine_id: engine.engine_id,
      name: engine.name,
      status: 'NOT_INSTALLED',
      executable: engine.executable,
      detected_path: null,
      version: null,
      checked_at: new Date().toISOString(),
      error: 'Not checked',
      capabilities: engine.capabilities,
    };

    return {
      engine_id: engine.engine_id,
      name: engine.name,
      version: engine.version,
      description: engine.description,
      executable: engine.executable,
      capabilities: engine.capabilities,
      supported_target_types: engine.supported_target_types,
      supported_languages: engine.supported_languages,
      availability: avail,
    };
  });

  res.json(results);
});

// GET /api/v1/engines/:engine_id - Get specific engine status and metadata
app.get('/api/v1/engines/:engine_id', async (req, res) => {
  const { engine_id } = req.params;
  const engine = globalEngineRegistry.get(engine_id);
  if (!engine) {
    return res.status(404).json({ error: `Engine '${engine_id}' not found in registry.` });
  }

  const availability = await engine.check_availability();
  res.json({
    engine_id: engine.engine_id,
    name: engine.name,
    version: engine.version,
    description: engine.description,
    executable: engine.executable,
    capabilities: engine.capabilities,
    supported_target_types: engine.supported_target_types,
    supported_languages: engine.supported_languages,
    availability,
  });
});

// POST /api/v1/engines/check - Force check availability for all registered engines
app.post('/api/v1/engines/check', async (req, res) => {
  const availability = await globalEngineRegistry.check_all();
  res.json({
    checked_at: new Date().toISOString(),
    count: availability.length,
    engines: availability,
  });
});

// POST /api/v1/engines/:engine_id/check - Force check availability for specific engine
app.post('/api/v1/engines/:engine_id/check', async (req, res) => {
  const { engine_id } = req.params;
  const engine = globalEngineRegistry.get(engine_id);
  if (!engine) {
    return res.status(404).json({ error: `Engine '${engine_id}' not found in registry.` });
  }

  const availability = await engine.check_availability();
  res.json(availability);
});

app.get('/api/taxonomy', (req, res) => {
  res.json(KNOWN_TAXONOMY);
});

app.post('/api/sandbox/validate', (req, res) => {
  const { command, target_in_scope } = req.body;
  const result = SandboxSecurityEnforcer.validateExecutionRequest(command || '', Boolean(target_in_scope));
  res.json({
    policy: DEFAULT_SANDBOX_POLICY,
    command,
    evaluation: result,
  });
});

// =============================================================
// Phase 2: Static & Structural Security Analysis Endpoints
// =============================================================

// POST /api/v1/investigations/:id/analysis/static - Trigger static analysis pipeline
app.post(['/api/v1/investigations/:id/analysis/static', '/api/investigations/:id/analysis/static'], async (req, res) => {
  try {
    const investigationId = req.params.id;
    const inv = globalDB.getInvestigation(investigationId);
    if (!inv) {
      return res.status(404).json({ error: `Investigation '${investigationId}' not found.` });
    }

    const { target_id, source_snapshot_id, source_directory } = req.body;
    const targetId = target_id || inv.target_id;

    // Resolve source snapshot and directory
    let snapshotId = source_snapshot_id;
    let sourceDir = source_directory;

    if (!snapshotId) {
      const snapshots = globalDB.listSourceSnapshots(targetId);
      if (snapshots.length > 0) {
        snapshotId = snapshots[0].id;
      } else {
        snapshotId = `snap-${targetId}-default`;
      }
    }

    if (!sourceDir) {
      // Default to root or fixtures if testing
      sourceDir = process.cwd();
    }

    // Create and queue an analysis job in the orchestrator
    const job = globalJobOrchestrator.createJob({
      id: `job-static-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      investigation_id: investigationId,
      target_id: targetId,
      engine: 'static-analysis',
      operation: 'static_analysis',
      metadata: {
        source_snapshot_id: snapshotId,
        source_directory: sourceDir,
      },
    });

    // Execute asynchronously in worker
    setTimeout(async () => {
      try {
        await globalJobOrchestrator.runJob(job.id, (artifact) => {
          globalDB.evidence.set(artifact.id, artifact);
          globalDB.rawArtifactStorage.set(artifact.id, artifact.content_preview || '');
          broadcastEvent('evidence_created', artifact);
        });
      } catch (err: any) {
        console.error('Static analysis job failed:', err);
      }
    }, 50);

    broadcastEvent('analysis_job_queued', {
      job_id: job.id,
      investigation_id: investigationId,
      target_id: targetId,
      engine: 'static-analysis',
    });

    res.status(202).json({
      message: 'Static analysis pipeline queued for execution.',
      job_id: job.id,
      investigation_id: investigationId,
      target_id: targetId,
      status: 'QUEUED',
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/investigations/:id/analysis/jobs - List analysis jobs for an investigation
app.get(['/api/v1/investigations/:id/analysis/jobs', '/api/investigations/:id/analysis/jobs'], (req, res) => {
  const jobs = globalJobOrchestrator.listJobs({ investigation_id: req.params.id });
  const analysisJobs = jobs.filter(j =>
    j.engine === 'static-analysis' ||
    j.engine === 'treesitter' ||
    j.engine === 'semgrep' ||
    j.operation.includes('analysis')
  );
  res.json(analysisJobs);
});

// GET /api/v1/investigations/:id/candidates - List candidate findings for an investigation
app.get(['/api/v1/investigations/:id/candidates', '/api/investigations/:id/candidates'], (req, res) => {
  const { status, category, severity, confidence } = req.query as any;
  const candidates = globalCandidateStore.listCandidates(req.params.id, {
    status,
    category,
    severity,
    confidence,
  });
  res.json(candidates);
});

// GET /api/v1/candidates/:id - Get a specific candidate finding
app.get(['/api/v1/candidates/:id', '/api/candidates/:id'], (req, res) => {
  const candidate = globalCandidateStore.getCandidate(req.params.id);
  if (!candidate) {
    return res.status(404).json({ error: `Candidate finding '${req.params.id}' not found.` });
  }
  res.json(candidate);
});

// GET /api/v1/candidates/:id/evidence - Get evidence artifacts and provenance chain for a candidate finding
app.get(['/api/v1/candidates/:id/evidence', '/api/candidates/:id/evidence'], (req, res) => {
  const candidate = globalCandidateStore.getCandidate(req.params.id);
  if (!candidate) {
    return res.status(404).json({ error: `Candidate finding '${req.params.id}' not found.` });
  }

  const evidence = globalCandidateStore.getEvidenceForCandidate(req.params.id);
  res.json({
    candidate_id: candidate.id,
    title: candidate.title,
    rule_id: candidate.rule_id,
    engine: candidate.engine,
    corroborated: candidate.corroborated,
    evidence_artifact_ids: candidate.evidence_artifact_ids,
    artifacts: evidence.artifacts,
    provenance_events: evidence.provenance_events,
  });
});

// POST /api/v1/candidates/:id/transition - Strictly controlled status transition with validation
app.post(['/api/v1/candidates/:id/transition', '/api/candidates/:id/transition'], (req, res) => {
  try {
    const { target_status, reason, actor } = req.body;
    if (!target_status || !reason) {
      return res.status(400).json({ error: 'target_status and reason are required.' });
    }

    const updated = globalCandidateStore.transitionStatus(
      req.params.id,
      target_status,
      reason,
      actor || 'security-researcher'
    );

    broadcastEvent('candidate_transitioned', updated);
    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// GET /api/v1/rules - List all registered security rules
app.get(['/api/v1/rules', '/api/rules'], (req, res) => {
  const { category, severity, language } = req.query as any;
  const rules = globalSecurityRuleRegistry.list({ category, severity, language });
  res.json(rules);
});

// GET /api/v1/rules/:id - Get specific security rule
app.get(['/api/v1/rules/:id', '/api/rules/:id'], (req, res) => {
  const rule = globalSecurityRuleRegistry.get(req.params.id);
  if (!rule) {
    return res.status(404).json({ error: `Rule '${req.params.id}' not found.` });
  }
  res.json(rule);
});

// =============================================================
// Vite Middleware / Static Handlers
// =============================================================
async function start() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Intent Security Workbench Server & WebSocket running on http://0.0.0.0:${PORT}`);
  });
}

start();

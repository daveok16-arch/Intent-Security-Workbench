#!/usr/bin/env tsx
/**
 * Intent Security Workbench CLI
 * Phase 0 & Phase 1 Scope & Target Authorization CLI
 *
 * Usage:
 *   intent programs list
 *   intent programs show <program_id>
 *   intent targets list [program_id]
 *   intent targets show <target_id>
 *   intent scope list [program_id]
 *   intent scope evaluate <target_id>
 *   intent source acquire <target_id>
 *   intent source verify <target_id>
 *   intent gate check <investigation_id>
 *   intent analyze static <investigation_id>
 *   intent analyze treesitter <investigation_id>
 *   intent analyze semgrep <investigation_id>
 *   intent candidates list [investigation_id]
 *   intent candidates show <candidate_id>
 *   intent rules list
 *   intent rules show <rule_id>
 *   intent engines list
 *   intent engines check [engine_id]
 *   intent evidence list [investigation_id]
 *   intent evidence show <artifact_id>
 *   intent evidence verify <artifact_id>
 *   intent provenance <investigation_id>
 *   intent events list [investigation_id]
 */

import { globalEngineRegistry } from './engines/engine_registry.js';
import { EngineAvailabilityStatus } from './engines/types.js';
import { globalDB } from './apps/api/db_store.js';
import { globalJobOrchestrator } from './packages/orchestrator/src/index.js';
import {
  globalTreeSitterService,
  globalSemgrepService,
  globalCandidateStore,
  globalSecurityRuleRegistry,
  executeStaticAnalysisPipeline,
} from './packages/static-analysis/src/index.js';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const subcommand = args[1];
  const param = args[2];

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    process.exit(0);
  }

  if (command === 'programs') {
    if (!subcommand || subcommand === 'list') {
      handleProgramsList();
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: program_id required. Usage: intent programs show <program_id>');
        process.exit(1);
      }
      handleProgramShow(param);
    } else {
      console.error(`Unknown programs subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'targets') {
    if (!subcommand || subcommand === 'list') {
      handleTargetsList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent targets show <target_id>');
        process.exit(1);
      }
      handleTargetShow(param);
    } else {
      console.error(`Unknown targets subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'scope') {
    if (!subcommand || subcommand === 'list') {
      handleScopeList(param);
    } else if (subcommand === 'evaluate') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent scope evaluate <target_id>');
        process.exit(1);
      }
      handleScopeEvaluate(param);
    } else {
      console.error(`Unknown scope subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'source') {
    if (subcommand === 'acquire') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source acquire <target_id>');
        process.exit(1);
      }
      await handleSourceAcquire(param);
    } else if (subcommand === 'status') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source status <target_id>');
        process.exit(1);
      }
      handleSourceStatus(param);
    } else if (subcommand === 'verify') {
      if (!param) {
        console.error('Error: target_id required. Usage: intent source verify <target_id>');
        process.exit(1);
      }
      await handleSourceVerify(param);
    } else {
      console.error(`Unknown source subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'gate') {
    if (subcommand === 'check' || subcommand === 'evaluate') {
      if (!param) {
        console.error('Error: investigation_id required. Usage: intent gate check <investigation_id>');
        process.exit(1);
      }
      handleGateCheck(param);
    } else {
      console.error(`Unknown gate subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'engines') {
    if (!subcommand || subcommand === 'list') {
      await handleEnginesList();
    } else if (subcommand === 'check') {
      if (param) {
        await handleEngineCheck(param);
      } else {
        await handleEnginesCheckAll();
      }
    } else {
      console.error(`Unknown engines subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'evidence') {
    if (!subcommand || subcommand === 'list') {
      await handleEvidenceList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: artifact_id is required. Usage: intent evidence show <artifact_id>');
        process.exit(1);
      }
      await handleEvidenceShow(param);
    } else if (subcommand === 'verify') {
      if (!param) {
        console.error('Error: artifact_id is required. Usage: intent evidence verify <artifact_id>');
        process.exit(1);
      }
      await handleEvidenceVerify(param);
    } else {
      console.error(`Unknown evidence subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'provenance') {
    const invId = subcommand;
    if (!invId) {
      console.error('Error: investigation_id is required. Usage: intent provenance <investigation_id>');
      process.exit(1);
    }
    await handleProvenance(invId);
  } else if (command === 'events') {
    await handleEventsList(subcommand);
  } else if (command === 'analyze') {
    if (!subcommand) {
      console.error('Error: analysis type required. Usage: intent analyze <static|treesitter|semgrep> <investigation_id>');
      process.exit(1);
    }
    await handleAnalyze(subcommand, param);
  } else if (command === 'candidates') {
    if (!subcommand || subcommand === 'list') {
      handleCandidatesList(param);
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: candidate_id is required. Usage: intent candidates show <candidate_id>');
        process.exit(1);
      }
      handleCandidateShow(param);
    } else {
      console.error(`Unknown candidates subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else if (command === 'rules') {
    if (!subcommand || subcommand === 'list') {
      handleRulesList();
    } else if (subcommand === 'show') {
      if (!param) {
        console.error('Error: rule_id is required. Usage: intent rules show <rule_id>');
        process.exit(1);
      }
      handleRuleShow(param);
    } else {
      console.error(`Unknown rules subcommand: '${subcommand}'`);
      process.exit(1);
    }
  } else {
    console.error(`Unknown command: '${command}'`);
    printHelp();
    process.exit(1);
  }
}

function printHelp() {
  console.log(`
INTENT SECURITY WORKBENCH CLI (Phase 2 Static & Structural Analysis)

Program & Scope Commands:
  intent programs list                  List registered security programs
  intent programs show <program_id>     Show program policy, status, and scope entries
  intent targets list [program_id]      List targets
  intent targets show <target_id>       Show target details, scope status, and snapshots
  intent scope list [program_id]        List normalized scope entries
  intent scope evaluate <target_id>     Execute deterministic scope evaluation with provenance
  intent source acquire <target_id>     Execute sandboxed Git clone/checkout & SHA-256 tree hashing
  intent source status <target_id>      Display source acquisition status and snapshot metadata
  intent source verify <target_id>      Verify local snapshot tree hash against stored digest
  intent gate check <investigation_id>  Pre-flight gate check (Authorization, Scope, Source, Policy)

Static & Structural Analysis Commands:
  intent analyze static <inv_id>        Execute unified Tree-sitter + Semgrep static analysis
  intent analyze treesitter <inv_id>    Execute Tree-sitter concrete syntax tree queries
  intent analyze semgrep <inv_id>       Execute Semgrep rule-based taint and pattern scan
  intent candidates list [inv_id]       List all candidate findings and verification states
  intent candidates show <cand_id>      Display detailed candidate finding, evidence & provenance
  intent rules list                     List data-driven static analysis security rules
  intent rules show <rule_id>           Show rule definition, pattern, CWE, and OWASP mapping

Engine Commands:
  intent engines list                   List registered engines and verified host availability
  intent engines check                  Execute real-time availability check across all engines
  intent engines check <engine_id>      Verify binary availability for a specific engine

Evidence & Provenance Commands:
  intent evidence list [inv_id]         List evidence artifacts
  intent evidence show <artifact_id>    Display detailed metadata and raw preview of an artifact
  intent evidence verify <artifact_id>  Compute actual SHA-256 and cryptographically verify integrity
  intent provenance <inv_id>            Traverse and display the complete investigation provenance graph
  intent events list [inv_id]           List immutable audit event trail
`);
}

function handleProgramsList() {
  const programs = globalDB.listPrograms();
  console.log('\nINTENT SECURITY WORKBENCH — SECURITY PROGRAMS');
  console.log('='.repeat(95));
  console.log(
    rpad('Program ID', 22) +
    rpad('Platform', 16) +
    rpad('Status', 12) +
    rpad('Scope Count', 14) +
    rpad('Name', 30)
  );
  console.log('-'.repeat(95));
  if (programs.length === 0) {
    console.log('(No programs registered)');
  } else {
    for (const prog of programs) {
      const scopeCount = globalDB.listScopeEntries(prog.id).length;
      console.log(
        rpad(prog.id, 22) +
        rpad(prog.platform, 16) +
        rpad(prog.status || 'ACTIVE', 12) +
        rpad(String(scopeCount), 14) +
        rpad(prog.name, 30)
      );
    }
  }
  console.log('-'.repeat(95));
  console.log(`Total Programs: ${programs.length}\n`);
}

function handleProgramShow(programId: string) {
  const prog = globalDB.getProgram(programId);
  if (!prog) {
    console.error(`Error: Program '${programId}' not found.`);
    process.exit(1);
  }
  const scope = globalDB.listScopeEntries(programId);

  console.log('\nPROGRAM RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:               ${prog.id}`);
  console.log(`Name:             ${prog.name}`);
  console.log(`Platform:         ${prog.platform}`);
  console.log(`Status:           ${prog.status}`);
  console.log(`Policy Version:   ${prog.policy_version}`);
  console.log(`Freshness:        ${prog.freshness_status}`);
  console.log(`Program URL:      ${prog.program_url || '(none)'}`);
  console.log(`Source Reference: ${prog.source_reference || '(none)'}`);
  console.log(`Retrieved At:     ${prog.retrieved_at}`);
  console.log(`Scope Entries:    ${scope.length}`);
  console.log('----------------------------------------------------');
  console.log('Scope Entries:\n');
  for (const s of scope) {
    console.log(`  [${s.inclusion_status}] (${s.asset_type}) ${s.asset_identifier}`);
  }
  console.log('\n');
}

function handleTargetsList(programId?: string) {
  const targets = globalDB.listTargets(programId);
  console.log(`\nINTENT SECURITY WORKBENCH — TARGETS${programId ? ` (Program: ${programId})` : ''}`);
  console.log('='.repeat(105));
  console.log(
    rpad('Target ID', 22) +
    rpad('Type', 16) +
    rpad('Scope Status', 16) +
    rpad('Auth Status', 16) +
    rpad('Source Status', 18) +
    rpad('Name', 17)
  );
  console.log('-'.repeat(105));
  if (targets.length === 0) {
    console.log('(No targets registered)');
  } else {
    for (const t of targets) {
      console.log(
        rpad(t.id, 22) +
        rpad(t.target_type, 16) +
        rpad(t.scope_status || 'NOT_EVALUATED', 16) +
        rpad(t.authorization_status || 'NOT_EVALUATED', 16) +
        rpad(t.source_acquisition_status || 'SOURCE_NOT_ACQUIRED', 18) +
        rpad(t.name, 17)
      );
    }
  }
  console.log('-'.repeat(105));
  console.log(`Total Targets: ${targets.length}\n`);
}

function handleTargetShow(targetId: string) {
  const target = globalDB.getTarget(targetId);
  if (!target) {
    console.error(`Error: Target '${targetId}' not found.`);
    process.exit(1);
  }
  const snapshots = globalDB.listSourceSnapshots(targetId);

  console.log('\nTARGET RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:                   ${target.id}`);
  console.log(`Program ID:           ${target.program_id}`);
  console.log(`Name:                 ${target.name}`);
  console.log(`Type:                 ${target.target_type}`);
  console.log(`Ecosystem:            ${target.ecosystem}`);
  console.log(`Identifier:           ${target.identifier || target.name}`);
  console.log(`Repo URL:             ${target.repository_url || '(none)'}`);
  console.log(`Commit Hash:          ${target.commit_hash || '(none)'}`);
  console.log(`Branch:               ${target.branch || '(none)'}`);
  console.log(`Scope Status:         ${target.scope_status}`);
  console.log(`Auth Status:          ${target.authorization_status}`);
  console.log(`Source Status:        ${target.source_acquisition_status}`);
  console.log(`Source Hash:          ${target.source_hash || '(none)'}`);
  console.log(`Source Snapshots:     ${snapshots.length}`);
  console.log('----------------------------------------------------\n');
}

function handleScopeList(programId?: string) {
  const entries = globalDB.listScopeEntries(programId);
  console.log(`\nINTENT SECURITY WORKBENCH — SCOPE ENTRIES${programId ? ` (Program: ${programId})` : ''}`);
  console.log('='.repeat(100));
  console.log(
    rpad('Entry ID', 22) +
    rpad('Inclusion', 16) +
    rpad('Asset Type', 18) +
    rpad('Asset Identifier', 44)
  );
  console.log('-'.repeat(100));
  if (entries.length === 0) {
    console.log('(No scope entries defined)');
  } else {
    for (const e of entries) {
      console.log(
        rpad(e.id, 22) +
        rpad(e.inclusion_status, 16) +
        rpad(e.asset_type, 18) +
        rpad(e.asset_identifier, 44)
      );
    }
  }
  console.log('-'.repeat(100));
  console.log(`Total Scope Entries: ${entries.length}\n`);
}

function handleScopeEvaluate(targetId: string) {
  console.log(`\n[!] Running deterministic scope evaluation for target '${targetId}'...`);
  try {
    const result = globalDB.evaluateTargetScope(targetId);
    console.log('\nSCOPE DECISION RESULT');
    console.log('----------------------------------------------------');
    console.log(`Decision:          ${result.decision}`);
    console.log(`Reason:            ${result.reason}`);
    console.log(`Evaluator Version: ${result.evaluator_version}`);
    console.log(`Policy Version:    ${result.policy_version}`);
    console.log(`Evaluated At:      ${result.evaluated_at}`);
    if (result.matched_scope_entry) {
      console.log(`Matched Entry:     ${result.matched_scope_entry.id} (${result.matched_scope_entry.asset_identifier})`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Evaluation failed:', err.message);
    process.exit(1);
  }
}

async function handleSourceAcquire(targetId: string) {
  console.log(`\n[!] Executing sandboxed Git source acquisition for target '${targetId}'...`);
  try {
    const result = await globalDB.acquireTargetSource(targetId);
    console.log('\nSOURCE ACQUISITION RESULT');
    console.log('----------------------------------------------------');
    console.log(`Success:           ${result.success ? '✔ SUCCESS' : '✖ FAILED'}`);
    console.log(`Resolved Commit:   ${result.resolved_commit_sha || '(none)'}`);
    console.log(`Deterministic Hash:${result.source_hash || '(none)'}`);
    console.log(`File Count:        ${result.file_count ?? 0}`);
    console.log(`Total Bytes:       ${result.total_bytes ?? 0}`);
    console.log(`Execution Time:    ${result.execution_time_ms} ms`);
    if (result.error) {
      console.log(`Error:             ${result.error}`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Acquisition failed:', err.message);
    process.exit(1);
  }
}

async function handleSourceVerify(targetId: string) {
  console.log(`\n[!] Verifying source integrity for target '${targetId}'...`);
  try {
    const result = await globalDB.verifyTargetSourceIntegrity(targetId);
    console.log('\nSOURCE INTEGRITY VERIFICATION');
    console.log('----------------------------------------------------');
    console.log(`Verified:          ${result.verified ? '✔ MATCH' : '✖ MISMATCH'}`);
    console.log(`Expected Hash:     ${result.expected_hash || '(none)'}`);
    console.log(`Calculated Hash:   ${result.actual_hash || '(none)'}`);
    if (result.error) {
      console.log(`Error:             ${result.error}`);
    }
    console.log('----------------------------------------------------\n');
  } catch (err: any) {
    console.error('Verification failed:', err.message);
    process.exit(1);
  }
}

function handleSourceStatus(targetId: string) {
  const target = globalDB.getTarget(targetId);
  if (!target) {
    console.error(`Error: Target '${targetId}' not found.`);
    process.exit(1);
  }
  const snapshots = globalDB.listSourceSnapshots(targetId);
  const latestSnapshot = snapshots[0];

  console.log('\nTARGET SOURCE ACQUISITION STATUS');
  console.log('----------------------------------------------------');
  console.log(`Target ID:            ${target.id}`);
  console.log(`Target Name:          ${target.name}`);
  console.log(`Source Status:        ${target.source_acquisition_status}`);
  console.log(`Source Hash:          ${target.source_hash || '(none)'}`);
  console.log(`Commit SHA:           ${target.commit_hash || '(none)'}`);
  console.log(`Branch:               ${target.branch || '(none)'}`);
  console.log(`Repository URL:       ${target.repository_url || '(none)'}`);
  console.log(`Snapshots Count:      ${snapshots.length}`);
  if (latestSnapshot) {
    console.log(`Latest Snapshot ID:   ${latestSnapshot.id}`);
    console.log(`Acquired At:          ${latestSnapshot.acquired_at || latestSnapshot.retrieval_timestamp || '(none)'}`);
    console.log(`Storage Path:         ${latestSnapshot.storage_path || '(none)'}`);
    console.log(`Provider:             ${latestSnapshot.provider} (v${latestSnapshot.provider_version})`);
  }
  console.log('----------------------------------------------------\n');
}

function handleGateCheck(investigationId: string) {
  console.log(`\n[!] Evaluating pre-flight investigation gate for '${investigationId}'...`);
  try {
    const gate = globalDB.evaluateInvestigationGate(investigationId);
    console.log('\nINVESTIGATION PRE-FLIGHT GATE RESULT');
    console.log('====================================================');
    console.log(`Overall Gate Status: ${gate.passed ? '✔ PASSED' : '✖ BLOCKED'}`);
    console.log(`Target Authorization: ${gate.target_authorization}`);
    console.log(`Scope Status:        ${gate.scope_status}`);
    console.log(`Source Status:       ${gate.source_status}`);
    console.log(`Policy Status:       ${gate.policy_status}`);
    console.log('----------------------------------------------------');
    console.log('Checks:');
    for (const check of gate.checks) {
      console.log(`  [${check.passed ? '✔ PASS' : '✖ FAIL'}] ${rpad(check.name, 28)} : ${check.message}`);
    }
    console.log('====================================================\n');
  } catch (err: any) {
    console.error('Gate check failed:', err.message);
    process.exit(1);
  }
}

async function handleEnginesList() {
  const engines = globalEngineRegistry.list();
  const availability = await globalEngineRegistry.check_all();

  console.log('\nINTENT SECURITY WORKBENCH — ENGINE REGISTRY');
  console.log('='.repeat(70));
  console.log(
    rpad('Engine', 24) +
    rpad('Status', 18) +
    rpad('Version', 24)
  );
  console.log('-'.repeat(70));

  for (const eng of engines) {
    const avail = availability.find(a => a.engine_id === eng.engine_id);
    const rawStatus = avail ? avail.status : EngineAvailabilityStatus.NOT_INSTALLED;
    const status = rawStatus === EngineAvailabilityStatus.NOT_INSTALLED ? 'NOT INSTALLED' : rawStatus;
    const version = (avail && avail.version) ? avail.version : '-';
    
    console.log(
      rpad(eng.engine_id, 24) +
      rpad(status, 18) +
      rpad(version, 24)
    );
  }
  console.log('-'.repeat(70));
  console.log(`Total Engines: ${engines.length} | Real binary verification verified at runtime.\n`);
}

async function handleEnginesCheckAll() {
  console.log('\n[!] Executing real host availability check across all registered engines...\n');
  const availability = await globalEngineRegistry.check_all();

  console.log(
    rpad('Engine ID', 22) +
    rpad('Status', 16) +
    rpad('Path', 20) +
    rpad('Version', 20)
  );
  console.log('-'.repeat(80));

  for (const item of availability) {
    const status = item.status === EngineAvailabilityStatus.NOT_INSTALLED ? 'NOT INSTALLED' : item.status;
    console.log(
      rpad(item.engine_id, 22) +
      rpad(status, 16) +
      rpad(item.detected_path || '(none)', 20) +
      rpad(item.version || '-', 20)
    );
  }
  console.log('-'.repeat(80));
  console.log(`Checked ${availability.length} engines at ${new Date().toISOString()}\n`);
}

async function handleEngineCheck(engineId: string) {
  console.log(`\n[!] Checking engine binary for: '${engineId}'...`);
  const engine = globalEngineRegistry.get(engineId);
  if (!engine) {
    console.error(`Error: Engine '${engineId}' is not registered in EngineRegistry.`);
    process.exit(1);
  }

  const avail = await engine.check_availability();
  console.log('\nENGINE VERIFICATION RESULT');
  console.log('-------------------------------------------');
  console.log(`Engine ID:     ${avail.engine_id}`);
  console.log(`Name:          ${avail.name}`);
  console.log(`Executable:    ${avail.executable}`);
  console.log(`Status:        ${avail.status}`);
  console.log(`Detected Path: ${avail.detected_path || '(none)'}`);
  console.log(`Version:       ${avail.version || '-'}`);
  console.log(`Error/Reason:  ${avail.error || '(none)'}`);
  console.log(`Capabilities:  ${avail.capabilities.join(', ')}`);
  console.log(`Checked At:    ${avail.checked_at}\n`);

  if (avail.status === EngineAvailabilityStatus.AVAILABLE) {
    console.log(`✔ Engine executable detected and verified on host PATH.\n`);
  } else {
    console.log(`✖ Engine executable is unavailable (${avail.status}). Never simulated.\n`);
  }
}

async function queryApi<T>(endpoint: string): Promise<T | null> {
  const apiUrl = process.env.API_URL || 'http://127.0.0.1:3000';
  try {
    const res = await fetch(`${apiUrl}${endpoint}`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      return await res.json() as T;
    }
  } catch {
    // API not reachable, fallback to direct in-memory / storage
  }
  return null;
}

async function handleEvidenceList(investigationId?: string) {
  let artifacts = await queryApi<any[]>(investigationId ? `/api/v1/investigations/${investigationId}/evidence` : '/api/v1/evidence');
  if (!artifacts) {
    artifacts = globalDB.listEvidence(investigationId);
  }
  console.log(`\nINTENT SECURITY WORKBENCH — EVIDENCE LOCKER${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(95));
  console.log(
    rpad('Artifact ID', 24) +
    rpad('Type', 18) +
    rpad('Producer', 20) +
    rpad('Size', 10) +
    rpad('SHA-256 Prefix', 20)
  );
  console.log('-'.repeat(95));

  if (artifacts.length === 0) {
    console.log('(No evidence artifacts recorded)');
  } else {
    for (const art of artifacts) {
      console.log(
        rpad(art.id, 24) +
        rpad(String(art.artifact_type), 18) +
        rpad(`${art.producer} (v${art.producer_version})`, 20) +
        rpad(`${art.size_bytes || art.byte_size || 0} B`, 10) +
        rpad(`${art.sha256.substring(0, 16)}...`, 20)
      );
    }
  }
  console.log('-'.repeat(95));
  console.log(`Total Artifacts: ${artifacts.length}\n`);
}

async function handleEvidenceShow(artifactId: string) {
  let art = await queryApi<any>(`/api/v1/evidence/${artifactId}`);
  if (!art) {
    art = globalDB.getEvidenceArtifact(artifactId);
  }
  if (!art) {
    console.error(`Error: Evidence artifact '${artifactId}' not found.`);
    process.exit(1);
  }

  console.log('\nEVIDENCE ARTIFACT RECORD');
  console.log('----------------------------------------------------');
  console.log(`ID:               ${art.id}`);
  console.log(`Investigation ID: ${art.investigation_id}`);
  console.log(`Artifact Type:    ${art.artifact_type}`);
  console.log(`Producer:         ${art.producer} (v${art.producer_version})`);
  console.log(`Command Executed: ${art.command || '(none)'}`);
  console.log(`Storage Path:     ${art.path || art.path_or_reference}`);
  console.log(`Size in Bytes:    ${art.size_bytes || art.byte_size} bytes`);
  console.log(`SHA-256 Digest:   ${art.sha256}`);
  console.log(`MIME Type:        ${art.mime_type || 'text/plain'}`);
  console.log(`Created At:       ${art.created_at}`);
  console.log('----------------------------------------------------');
  console.log('Content Preview:\n');
  console.log(art.content_preview || '(No preview available)');
  console.log('\n');
}

async function handleEvidenceVerify(artifactId: string) {
  console.log(`\n[!] Calculating actual SHA-256 byte digest for: '${artifactId}'...`);
  let integrity = await queryApi<any>(`/api/v1/evidence/${artifactId}/integrity`);
  if (!integrity) {
    integrity = await globalDB.verifyArtifactIntegrity(artifactId);
  }

  console.log('\nCRYPTOGRAPHIC INTEGRITY REPORT');
  console.log('----------------------------------------------------');
  console.log(`Artifact ID:     ${artifactId}`);
  console.log(`Expected SHA:    ${integrity.expected_sha256}`);
  console.log(`Actual SHA:      ${integrity.actual_sha256 || '(unreadable)'}`);
  console.log(`Size Checked:    ${integrity.size_bytes} bytes`);
  console.log(`Integrity State: ${integrity.status}`);
  if (integrity.error) {
    console.log(`Error:           ${integrity.error}`);
  }
  console.log('----------------------------------------------------');

  if (integrity.valid) {
    console.log('✔ PASS: Stored bytes match exact cryptographic digest.\n');
  } else {
    console.log('✖ FAIL: Cryptographic signature mismatch or artifact missing.\n');
  }
}

async function handleProvenance(investigationId: string) {
  let graph = await queryApi<any>(`/api/v1/investigations/${investigationId}/provenance`);
  let invTitle = investigationId;
  if (!graph) {
    const inv = globalDB.getInvestigation(investigationId);
    if (!inv) {
      console.error(`Error: Investigation '${investigationId}' not found.`);
      process.exit(1);
    }
    invTitle = inv.title;
    const jobs = globalJobOrchestrator.listJobs({ investigation_id: investigationId });
    graph = globalDB.getInvestigationProvenance(investigationId, jobs);
  }

  console.log(`\nPROVENANCE GRAPH — INVESTIGATION: '${invTitle}' (${investigationId})`);
  console.log('='.repeat(80));
  console.log(`Generated At: ${graph.generated_at}`);
  console.log(`Total Nodes:  ${graph.nodes.length}`);
  console.log(`Total Edges:  ${graph.edges.length}\n`);

  console.log('GRAPH NODES:');
  console.log('-'.repeat(80));
  for (const node of graph.nodes) {
    console.log(`  [${rpad(node.type, 16)}] ${rpad(node.id, 24)} -> ${node.label}`);
  }

  console.log('\nGRAPH RELATIONSHIPS (EDGES):');
  console.log('-'.repeat(80));
  for (const edge of graph.edges) {
    console.log(`  ${rpad(edge.source, 24)} --[ ${rpad(edge.relationship, 20)} ]--> ${edge.target}`);
  }
  console.log('='.repeat(80) + '\n');
}

async function handleEventsList(investigationId?: string) {
  const events = globalDB.listEvidenceEvents(investigationId);
  console.log(`\nIMMUTABLE EVIDENCE EVENT LOG${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(95));
  console.log(
    rpad('Event ID', 22) +
    rpad('Event Type', 22) +
    rpad('Actor', 18) +
    rpad('Producer', 18) +
    rpad('Timestamp', 15)
  );
  console.log('-'.repeat(95));

  if (events.length === 0) {
    console.log('(No events recorded)');
  } else {
    for (const ev of events) {
      console.log(
        rpad(ev.id, 22) +
        rpad(String(ev.event_type), 22) +
        rpad(ev.actor, 18) +
        rpad(ev.producer, 18) +
        rpad(new Date(ev.timestamp).toLocaleTimeString(), 15)
      );
    }
  }
  console.log('-'.repeat(95) + '\n');
}

async function handleAnalyze(type: string, investigationId?: string) {
  if (!investigationId) {
    console.error(`Error: investigation_id is required. Usage: intent analyze ${type} <investigation_id>`);
    process.exit(1);
  }

  const inv = globalDB.getInvestigation(investigationId);
  if (!inv) {
    console.error(`Error: Investigation '${investigationId}' not found.`);
    process.exit(1);
  }

  const target = globalDB.getTarget(inv.target_id);
  const snapshots = globalDB.listSourceSnapshots(inv.target_id);
  const snapshotId = snapshots.length > 0 ? snapshots[0].id : `snap-${inv.target_id}-default`;
  const sourceDir = process.cwd();

  console.log(`\n========================================================================`);
  console.log(`INTENT WORKBENCH — STATIC & STRUCTURAL SECURITY ANALYSIS`);
  console.log(`========================================================================`);
  console.log(`Investigation:   ${inv.id} (${inv.title})`);
  console.log(`Target:          ${target ? target.name : inv.target_id}`);
  console.log(`Analysis Mode:   ${type.toUpperCase()}`);
  console.log(`Source Snapshot: ${snapshotId}`);
  console.log(`Working Dir:     ${sourceDir}`);
  console.log(`Started At:      ${new Date().toISOString()}\n`);

  if (type === 'static' || type === 'all') {
    console.log(`[*] Executing multi-engine static analysis pipeline (Tree-sitter + Semgrep)...`);
    const result = await executeStaticAnalysisPipeline(
      inv.id,
      inv.target_id,
      snapshotId,
      sourceDir
    );

    console.log(`\nEXECUTION BREAKDOWN:`);
    console.log(`------------------------------------------------------------------------`);
    console.log(`Tree-sitter:     Status: ${result.treesitter.status} | Files: ${result.treesitter.files_scanned} | Errors: ${result.treesitter.parse_errors} | Duration: ${result.treesitter.duration_ms}ms`);
    console.log(`Semgrep:         Status: ${result.semgrep.status} | Exit Code: ${result.semgrep.exit_code} | Duration: ${result.semgrep.duration_ms}ms`);
    console.log(`Correlation:     Candidates: ${result.correlation.candidates_created} | Corroborated: ${result.correlation.corroborated_candidates}`);
    console.log(`Total Duration:  ${result.total_duration_ms}ms\n`);

    console.log(`CANDIDATE VULNERABILITY FINDINGS (INITIAL STATE: CANDIDATE):`);
    console.log(`========================================================================`);
    console.log(
      rpad('Candidate ID', 22) +
      rpad('Rule ID', 18) +
      rpad('Severity', 10) +
      rpad('Conf', 8) +
      rpad('Engine', 24) +
      rpad('Location', 18)
    );
    console.log(`-`.repeat(100));

    if (result.candidates.length === 0) {
      console.log(`(No candidate findings detected in target source)`);
    } else {
      for (const c of result.candidates) {
        console.log(
          rpad(c.id, 22) +
          rpad(c.rule_id, 18) +
          rpad(c.severity, 10) +
          rpad(c.confidence, 8) +
          rpad(c.engine, 24) +
          rpad(`${c.file_path}:${c.line_start}`, 18)
        );
      }
    }
    console.log(`========================================================================\n`);

  } else if (type === 'treesitter') {
    console.log(`[*] Executing Tree-sitter concrete syntax tree analysis...`);
    const scan = await globalTreeSitterService.scanDirectory(
      sourceDir,
      snapshotId,
      inv.id,
      inv.target_id
    );

    console.log(`Files scanned: ${scan.results.length}`);
    console.log(`AST Artifacts created: ${scan.artifactIds.length}`);
    console.log(`Candidates identified: ${scan.candidates.length}\n`);

    for (const c of scan.candidates) {
      globalCandidateStore.addCandidate(c);
      console.log(`  -> [CANDIDATE] ${c.rule_id} (${c.severity}) at ${c.file_path}:${c.line_start} [${c.confidence}]`);
    }
  } else if (type === 'semgrep') {
    console.log(`[*] Executing Semgrep CLI scan...`);
    const scan = await globalSemgrepService.executeScan(
      sourceDir,
      snapshotId,
      inv.id,
      inv.target_id
    );

    console.log(`Exit code: ${scan.execution.exit_code}`);
    console.log(`Raw matches: ${scan.execution.raw_findings_count}`);
    console.log(`Duration: ${scan.execution.duration_ms}ms\n`);

    for (const c of scan.candidates) {
      globalCandidateStore.addCandidate(c);
      console.log(`  -> [CANDIDATE] ${c.rule_id} (${c.severity}) at ${c.file_path}:${c.line_start} [${c.confidence}]`);
    }
  } else {
    console.error(`Unknown analysis type: '${type}'. Options: static, treesitter, semgrep`);
    process.exit(1);
  }
}

function handleCandidatesList(investigationId?: string) {
  const candidates = globalCandidateStore.listCandidates(investigationId);
  console.log(`\nCANDIDATE FINDINGS LEDGER${investigationId ? ` (Investigation: ${investigationId})` : ''}`);
  console.log('='.repeat(105));
  console.log(
    rpad('Candidate ID', 22) +
    rpad('Status', 14) +
    rpad('Rule ID', 18) +
    rpad('Severity', 10) +
    rpad('Confidence', 12) +
    rpad('Corroborated', 14) +
    rpad('File:Line', 15)
  );
  console.log('-'.repeat(105));

  if (candidates.length === 0) {
    console.log('(No candidates in store)');
  } else {
    for (const c of candidates) {
      console.log(
        rpad(c.id, 22) +
        rpad(c.status, 14) +
        rpad(c.rule_id, 18) +
        rpad(c.severity, 10) +
        rpad(c.confidence, 12) +
        rpad(c.corroborated ? 'YES' : 'NO', 14) +
        rpad(`${c.file_path}:${c.line_start}`, 15)
      );
    }
  }
  console.log('-'.repeat(105));
  console.log(`Total Candidates: ${candidates.length}\n`);
}

function handleCandidateShow(candidateId: string) {
  const c = globalCandidateStore.getCandidate(candidateId);
  if (!c) {
    console.error(`Error: Candidate '${candidateId}' not found.`);
    process.exit(1);
  }

  const evidence = globalCandidateStore.getEvidenceForCandidate(candidateId);

  console.log('\n========================================================================');
  console.log(`CANDIDATE FINDING: ${c.id}`);
  console.log('========================================================================');
  console.log(`Title:             ${c.title}`);
  console.log(`Rule ID:           ${c.rule_id}`);
  console.log(`Status:            ${c.status} (Verified entry state)`);
  console.log(`Category:          ${c.category}`);
  console.log(`Severity:          ${c.severity}`);
  console.log(`Confidence:        ${c.confidence}`);
  console.log(`Confidence Basis:  ${c.confidence_basis}`);
  console.log(`Corroborated:      ${c.corroborated ? 'TRUE (Multiple engines concurred)' : 'FALSE'}`);
  console.log(`Engine:            ${c.engine}`);
  console.log(`File:              ${c.file_path}:${c.line_start}-${c.line_end}`);
  console.log(`Investigation ID:  ${c.investigation_id}`);
  console.log(`Target ID:         ${c.target_id}`);
  console.log(`Source Snapshot:   ${c.source_snapshot_id}`);
  console.log(`Created At:        ${c.created_at}`);

  if (c.cwe_ids?.length) {
    console.log(`CWE:               ${c.cwe_ids.join(', ')}`);
  }
  if (c.owasp_categories?.length) {
    console.log(`OWASP:             ${c.owasp_categories.join(', ')}`);
  }

  console.log('\nMATCHED CODE EVIDENCE:');
  console.log('------------------------------------------------------------------------');
  console.log(c.matched_code);
  console.log('------------------------------------------------------------------------');

  console.log(`\nEVIDENCE ARTIFACTS (${c.evidence_artifact_ids.length}):`);
  for (const art of evidence.artifacts) {
    console.log(`  - [${art.artifact_type}] ${art.id} | SHA-256: ${art.sha256}`);
  }

  console.log(`\nPROVENANCE EVENTS (${evidence.provenance_events.length}):`);
  for (const ev of evidence.provenance_events) {
    console.log(`  - [${ev.event_type}] by ${ev.actor} at ${new Date(ev.timestamp).toLocaleTimeString()}`);
  }

  console.log('\nSTATUS HISTORY:');
  for (const h of c.status_history) {
    console.log(`  - ${h.from_status} -> ${h.to_status} by ${h.actor} (${new Date(h.timestamp).toLocaleTimeString()}): ${h.reason}`);
  }
  console.log('========================================================================\n');
}

function handleRulesList() {
  const rules = globalSecurityRuleRegistry.list();
  console.log('\nINTENT SECURITY WORKBENCH — SECURITY RULE REGISTRY');
  console.log('='.repeat(95));
  console.log(
    rpad('Rule ID', 20) +
    rpad('Category', 18) +
    rpad('Severity', 10) +
    rpad('Languages', 18) +
    rpad('Title', 29)
  );
  console.log('-'.repeat(95));

  for (const r of rules) {
    console.log(
      rpad(r.id, 20) +
      rpad(r.category, 18) +
      rpad(r.severity, 10) +
      rpad(r.languages.join(','), 18) +
      rpad(r.title, 29)
    );
  }
  console.log('-'.repeat(95));
  console.log(`Total Registered Rules: ${rules.length}\n`);
}

function handleRuleShow(ruleId: string) {
  const r = globalSecurityRuleRegistry.get(ruleId);
  if (!r) {
    console.error(`Error: Rule '${ruleId}' not found.`);
    process.exit(1);
  }

  console.log('\n========================================================================');
  console.log(`RULE: ${r.id} - ${r.title}`);
  console.log('========================================================================');
  console.log(`Description:  ${r.description}`);
  console.log(`Category:     ${r.category}`);
  console.log(`Severity:     ${r.severity}`);
  console.log(`Languages:    ${r.languages.join(', ')}`);
  console.log(`CWE IDs:      ${r.cwe_ids.join(', ')}`);
  console.log(`OWASP:        ${r.owasp_categories.join(', ')}`);
  console.log(`Engine:       ${r.engine_support.join(', ')}`);
  console.log(`Version:      ${r.version}`);
  console.log('\nRULE PATTERNS:');
  console.log(JSON.stringify(r.patterns, null, 2));
  console.log('========================================================================\n');
}

function rpad(str: string, length: number): string {
  if (str.length >= length) {
    return str.substring(0, length - 1) + ' ';
  }
  return str + ' '.repeat(length - str.length);
}

main().catch(err => {
  console.error('CLI Error:', err);
  process.exit(1);
});

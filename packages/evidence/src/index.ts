/**
 * Evidence & Provenance Tracking System for Intent Security Workbench
 * Phase 0.2 Evidence & Provenance Subsystem
 *
 * Ground-truth evidence locker, append-only event trail, filesystem artifact storage,
 * and deterministic cryptographic provenance graphs.
 */

import { createHash } from 'crypto';
import { ArtifactType, EvidenceArtifact } from '../../core/src/index.js';
import { LocalFilesystemArtifactStorage } from './storage/local_storage.js';
import { IArtifactStorage, ArtifactIntegrityResult } from './storage/storage_interface.js';

export * from './storage/storage_interface.js';
export * from './storage/local_storage.js';
export * from './provenance.js';
export * from './events.js';
export * from './snapshot.js';

export const globalArtifactStorage: IArtifactStorage = new LocalFilesystemArtifactStorage();

/**
 * Computes exact cryptographic SHA-256 hash over raw byte content or string data.
 * No mock/simulated hashes.
 */
export function computeArtifactSHA256(content: string | Buffer): string {
  const hash = createHash('sha256');
  if (typeof content === 'string') {
    hash.update(Buffer.from(content, 'utf-8'));
  } else {
    hash.update(content);
  }
  return hash.digest('hex');
}

/**
 * Verifies that an artifact's recorded SHA-256 matches its actual binary content.
 */
export function verifyArtifactIntegrity(
  artifact: EvidenceArtifact,
  actualContent?: string | Buffer
): { valid: boolean; status: 'VALID' | 'INVALID'; expected_sha256: string; actual_sha256: string; expected?: string; actual?: string } {
  if (actualContent !== undefined) {
    const actualHash = computeArtifactSHA256(actualContent);
    const valid = artifact.sha256.toLowerCase() === actualHash.toLowerCase();
    return {
      valid,
      status: valid ? 'VALID' : 'INVALID',
      expected_sha256: artifact.sha256,
      actual_sha256: actualHash,
      expected: artifact.sha256,
      actual: actualHash,
    };
  }
  return {
    valid: false,
    status: 'INVALID',
    expected_sha256: artifact.sha256,
    actual_sha256: '',
    expected: artifact.sha256,
    actual: '',
  };
}

/**
 * Constructs a real, machine-verifiable EvidenceArtifact with SHA-256 hash and metadata.
 */
export function createEvidenceArtifact(params: {
  id: string;
  investigation_id: string;
  target_id?: string;
  artifact_type: ArtifactType | string;
  producer: string;
  producer_version: string;
  command?: string;
  working_directory?: string;
  source_snapshot_id?: string | null;
  target_hash?: string;
  content: string | Buffer;
  path_or_reference?: string;
  path?: string;
  mime_type?: string;
  metadata?: Record<string, any>;
}): { artifact: EvidenceArtifact; rawContent: string | Buffer } {
  const rawContent = params.content;
  const sha256 = computeArtifactSHA256(rawContent);
  const size_bytes = typeof rawContent === 'string' ? Buffer.byteLength(rawContent, 'utf-8') : rawContent.length;
  
  const contentPreview = typeof rawContent === 'string'
    ? rawContent.slice(0, 500)
    : `[Binary content: ${size_bytes} bytes]`;

  const relPath = params.path || params.path_or_reference || `evidence/${params.id}.bin`;
  const mime = params.mime_type || (typeof rawContent === 'string' ? 'text/plain' : 'application/octet-stream');

  const artifact: EvidenceArtifact = {
    id: params.id,
    investigation_id: params.investigation_id,
    target_id: params.target_id,
    artifact_type: params.artifact_type,
    producer: params.producer,
    producer_version: params.producer_version,
    source_snapshot_id: params.source_snapshot_id,
    command: params.command || '',
    working_directory: params.working_directory,
    target_hash: params.target_hash,
    path: relPath,
    size_bytes,
    sha256,
    mime_type: mime,
    // Aliases
    byte_size: size_bytes,
    path_or_reference: relPath,
    content_preview: contentPreview,
    metadata: params.metadata || {},
    created_at: new Date().toISOString(),
  };

  return { artifact, rawContent };
}


/**
 * Base Engine Class
 * Intent Security Workbench - Phase 0.1
 *
 * Provides typed base execution semantics, accurate binary verification,
 * and strict anti-fabrication invariants across all security analysis engines.
 */

import { execSync, execFileSync } from 'child_process';
import os from 'os';
import {
  IEngine,
  EngineAvailability,
  EngineAvailabilityStatus,
  EngineResult,
  EngineResultStatus,
  EngineFinding,
  EngineArtifact,
} from './types.js';

export abstract class BaseEngine implements IEngine {
  abstract readonly name: string;
  abstract readonly engine_id: string;
  abstract readonly version: string;
  abstract readonly description: string;
  abstract readonly capabilities: string[];
  abstract readonly supported_target_types: string[];
  abstract readonly supported_languages: string[];
  abstract readonly executable: string;

  /**
   * CLI argument(s) used for extracting the actual engine version.
   * Defaults to ['--version'].
   */
  protected versionArgs: string[] = ['--version'];

  /**
   * Helper property for backward compatibility with Phase 0 checks.
   */
  get binaryName(): string {
    return this.executable;
  }

  /**
   * Check executable availability in the real environment.
   * Never fabricates availability or versions.
   */
  async check_availability(): Promise<EngineAvailability> {
    const checked_at = new Date().toISOString();

    // 1. Check if executable exists in PATH
    let detectedPath: string | null = null;
    try {
      // Validate executable name does not contain shell injection characters
      if (!/^[a-zA-Z0-9_-]+$/.test(this.executable)) {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.UNAVAILABLE,
          executable: this.executable,
          detected_path: null,
          version: null,
          checked_at,
          error: `Invalid executable identifier '${this.executable}'.`,
          capabilities: this.capabilities,
        };
      }

      const out = execSync(`which ${this.executable}`, {
        encoding: 'utf-8',
        timeout: 2000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      if (out) {
        detectedPath = out;
      }
    } catch {
      // Binary not found on system PATH
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        capabilities: this.capabilities,
      };
    }

    if (!detectedPath) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.NOT_INSTALLED,
        executable: this.executable,
        detected_path: null,
        version: null,
        checked_at,
        error: `Executable '${this.executable}' is not installed or not found on system PATH.`,
        capabilities: this.capabilities,
      };
    }

    // 2. Executable exists on PATH. Test actual execution by querying real version.
    try {
      const realVersion = await this.get_version();
      if (realVersion) {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.AVAILABLE,
          executable: this.executable,
          detected_path: detectedPath,
          version: realVersion,
          checked_at,
          error: null,
          capabilities: this.capabilities,
        };
      } else {
        return {
          engine_id: this.engine_id,
          name: this.name,
          status: EngineAvailabilityStatus.BROKEN,
          executable: this.executable,
          detected_path: detectedPath,
          version: null,
          checked_at,
          error: `Binary at '${detectedPath}' exists but failed to return a valid version string.`,
          capabilities: this.capabilities,
        };
      }
    } catch (err: any) {
      return {
        engine_id: this.engine_id,
        name: this.name,
        status: EngineAvailabilityStatus.BROKEN,
        executable: this.executable,
        detected_path: detectedPath,
        version: null,
        checked_at,
        error: `Binary at '${detectedPath}' threw error during execution: ${err.message || String(err)}`,
        capabilities: this.capabilities,
      };
    }
  }

  /**
   * Alias for backward compatibility.
   */
  async check_available(): Promise<{
    available: boolean;
    name: string;
    version?: string;
    binary_path?: string;
    reason?: string;
    checked_at: string;
    status?: EngineAvailabilityStatus;
  }> {
    const avail = await this.check_availability();
    return {
      available: avail.status === EngineAvailabilityStatus.AVAILABLE,
      name: this.name,
      version: avail.version || undefined,
      binary_path: avail.detected_path || undefined,
      reason: avail.error || undefined,
      checked_at: avail.checked_at,
      status: avail.status,
    };
  }

  /**
   * Query the actual executable for its real version string.
   * Returns null if binary is missing or cannot execute.
   */
  async get_version(): Promise<string | null> {
    try {
      const output = execFileSync(this.executable, this.versionArgs, {
        encoding: 'utf-8',
        timeout: 3000,
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();

      if (!output) return null;
      // Extract the first meaningful line or version token
      const firstLine = output.split('\n')[0].trim();
      return firstLine || output;
    } catch {
      return null;
    }
  }

  abstract prepare(targetId: string, context: Record<string, any>): Promise<boolean>;

  abstract execute(
    targetId: string,
    operation: string,
    context: Record<string, any>
  ): Promise<EngineResult>;

  abstract parse_result(rawOutput: { stdout: string; stderr: string; exit_code: number }): EngineFinding[];

  abstract cleanup(context: Record<string, any>): Promise<void>;

  /**
   * Standard environment information for result provenance.
   */
  protected getEnvironmentInfo(detectedPath?: string | null) {
    return {
      hostname: os.hostname(),
      os: `${os.type()} ${os.release()} (${os.arch()})`,
      node_version: process.version,
      executable_path: detectedPath || null,
    };
  }
}

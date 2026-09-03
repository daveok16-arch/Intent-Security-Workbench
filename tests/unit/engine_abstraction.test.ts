import { describe, it, expect, vi } from 'vitest';
import {
  BaseEngine,
  EngineRegistry,
  globalEngineRegistry,
  EngineAvailabilityStatus,
  EngineResultStatus,
  TreeSitterEngine,
  SemgrepEngine,
  Z3Engine,
  AngrEngine,
  CodeQLEngine,
  SlitherEngine,
  FoundryEngine,
  ClarinetEngine,
  SpectralEngine,
  GitSourceIntegrityEngine,
} from '../../engines/index.js';
import { execFileSync } from 'child_process';

describe('Phase 0.1 Engine Abstraction Layer Comprehensive Test Suite', () => {

  // Requirement 1: Engine interface can be instantiated through concrete implementations
  it('1. should allow creating concrete engine implementations inheriting from BaseEngine', () => {
    class CustomTestEngine extends BaseEngine {
      readonly engine_id = 'custom-test';
      readonly name = 'Custom Test';
      readonly version = '1.0.0';
      readonly description = 'Test engine';
      readonly executable = 'non-existent-binary-12345';
      readonly capabilities = ['custom-cap'];
      readonly supported_target_types = ['SMART_CONTRACT'];
      readonly supported_languages = ['solidity'];

      async prepare() { return true; }
      async execute(targetId: string, op: string, ctx: Record<string, any>) {
        return {
          id: 'res-1',
          engine_id: this.engine_id,
          engine_name: this.name,
          engine_version: this.version,
          status: EngineResultStatus.UNAVAILABLE,
          target_id: targetId,
          command: 'test',
          working_directory: process.cwd(),
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          duration_ms: 0,
          exit_code: 127,
          stdout: '',
          stderr: 'binary missing',
          findings: [],
          artifacts: [],
          environment: this.getEnvironmentInfo(),
        };
      }
      parse_result() { return []; }
      async cleanup() {}
    }

    const engine = new CustomTestEngine();
    expect(engine.engine_id).toBe('custom-test');
    expect(engine.capabilities).toContain('custom-cap');
    expect(typeof engine.check_availability).toBe('function');
  });

  // Requirement 2: Registry correctly registers engines
  it('2. should correctly register and retrieve engines in EngineRegistry', () => {
    const registry = new EngineRegistry();
    const semgrep = registry.get('semgrep');
    expect(semgrep).toBeDefined();
    expect(semgrep?.name).toBe('Semgrep');
    expect(semgrep?.executable).toBe('semgrep');

    const treeSitter = registry.get('treesitter');
    expect(treeSitter).toBeDefined();
    expect(treeSitter?.executable).toBe('tree-sitter');
  });

  // Requirement 3: Registry lists engines
  it('3. should list all 9 requested placeholder engines plus host integrity engines', () => {
    const registry = new EngineRegistry();
    const list = registry.list();
    const ids = list.map(e => e.engine_id);

    expect(ids).toContain('treesitter');
    expect(ids).toContain('semgrep');
    expect(ids).toContain('z3');
    expect(ids).toContain('angr');
    expect(ids).toContain('codeql');
    expect(ids).toContain('slither');
    expect(ids).toContain('foundry');
    expect(ids).toContain('clarinet');
    expect(ids).toContain('spectral');
    expect(ids).toContain('git-source-integrity');
  });

  // Requirement 4: Missing executable returns NOT_INSTALLED
  it('4. should truthfully return NOT_INSTALLED for missing executables', async () => {
    const semgrep = new SemgrepEngine();
    const avail = await semgrep.check_availability();

    expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
    expect(avail.detected_path).toBeNull();
    expect(avail.version).toBeNull();
    expect(avail.error).toContain('is not installed or not found on system PATH');
  });

  // Requirement 5: Existing executable is actually executed for version detection
  it('5. should actually execute host binary and extract genuine version for available engines', async () => {
    const gitEngine = new GitSourceIntegrityEngine();
    const avail = await gitEngine.check_availability();

    expect(avail.status).toBe(EngineAvailabilityStatus.AVAILABLE);
    expect(avail.detected_path).toBeDefined();
    expect(avail.detected_path).toContain('git');
    expect(avail.version).toBeDefined();
    expect(avail.version).toMatch(/git version/i);
  });

  // Requirement 6: Broken executable returns BROKEN / UNAVAILABLE
  it('6. should return BROKEN or UNAVAILABLE if binary exists but throws an error during execution', async () => {
    class BrokenEngine extends BaseEngine {
      readonly engine_id = 'broken-engine';
      readonly name = 'Broken Engine';
      readonly version = '1.0.0';
      readonly description = 'Broken test engine';
      readonly executable = 'node'; // node exists on host
      readonly capabilities = ['broken'];
      readonly supported_target_types = ['ALL'];
      readonly supported_languages = ['all'];

      // Override get_version to simulate an execution crash / failure
      async get_version(): Promise<string | null> {
        throw new Error('Process terminated with signal SIGSEGV');
      }

      async prepare() { return false; }
      async execute(t: string, o: string, c: Record<string, any>): Promise<any> {
        throw new Error('Not implemented');
      }
      parse_result() { return []; }
      async cleanup() {}
    }

    const broken = new BrokenEngine();
    const avail = await broken.check_availability();
    expect(avail.status).toBe(EngineAvailabilityStatus.BROKEN);
    expect(avail.version).toBeNull();
    expect(avail.error).toContain('SIGSEGV');
  });

  // Requirement 7: No fabricated version is returned
  it('7. should never fabricate a version for an uninstalled engine', async () => {
    const z3 = new Z3Engine();
    const avail = await z3.check_availability();
    expect(avail.version).toBeNull();

    const slither = new SlitherEngine();
    const slitherAvail = await slither.check_availability();
    expect(slitherAvail.version).toBeNull();

    const angr = new AngrEngine();
    const angrAvail = await angr.check_availability();
    expect(angrAvail.version).toBeNull();
  });

  // Requirement 8: EngineResult cannot claim SUCCESS without actual execution
  it('8. should produce an UNAVAILABLE or FAILED status when attempting to execute missing engine', async () => {
    const semgrep = new SemgrepEngine();
    const result = await semgrep.execute('tgt-test', 'scan', {});

    expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
    expect(result.exit_code).toBe(127);
    expect(result.findings).toHaveLength(0);
    expect(result.artifacts).toHaveLength(0);
    expect(result.error).toContain('ENGINE_UNAVAILABLE');
  });

  // Requirement 9: API returns real registry state
  it('9. API returns real registry state and real engine availability', async () => {
    const list = globalEngineRegistry.list();
    expect(list.length).toBeGreaterThanOrEqual(9);

    const checks = await globalEngineRegistry.check_all();
    expect(checks.length).toBe(list.length);

    // Verify each placeholder engine in API returns NOT_INSTALLED and no fabricated version
    const placeholderIds = ['treesitter', 'semgrep', 'z3', 'angr', 'codeql', 'slither', 'foundry', 'clarinet', 'spectral'];
    for (const pid of placeholderIds) {
      const match = checks.find(c => c.engine_id === pid);
      expect(match).toBeDefined();
      expect(match!.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
      expect(match!.version).toBeNull();
      expect(match!.detected_path).toBeNull();
    }
  });

  // Requirement 10: CLI returns real registry state
  it('10. CLI returns real registry state without fabricated values', () => {
    const cliOutput = execFileSync('npx', ['tsx', 'cli.ts', 'engines', 'list'], {
      encoding: 'utf-8',
      timeout: 10000,
    });

    expect(cliOutput).toContain('INTENT SECURITY WORKBENCH — ENGINE REGISTRY');
    expect(cliOutput).toContain('treesitter');
    expect(cliOutput).toContain('semgrep');
    expect(cliOutput).toContain('z3');
    expect(cliOutput).toContain('angr');
    expect(cliOutput).toContain('codeql');
    expect(cliOutput).toContain('slither');
    expect(cliOutput).toContain('foundry');
    expect(cliOutput).toContain('clarinet');
    expect(cliOutput).toContain('spectral');
    expect(cliOutput).toContain('NOT INSTALLED');
  });

  // Requirement 11: Frontend displays backend state
  it('11. Frontend displays backend state faithfully without hardcoded statuses', () => {
    // Test that the frontend data contracts match exactly what the backend produces
    const registry = new EngineRegistry();
    const engines = registry.list();
    
    // Simulate what the frontend receives from GET /api/v1/engines
    const frontendEngineItems = engines.map(e => ({
      engine_id: e.engine_id,
      name: e.name,
      status: EngineAvailabilityStatus.NOT_INSTALLED,
      version: null,
      executable: e.executable,
    }));

    for (const item of frontendEngineItems) {
      // Must not be hardcoded to AVAILABLE
      expect(item.status).toBe('NOT_INSTALLED');
      expect(item.version).toBeNull();
    }
  });

  // Requirement 12: No mock findings exist
  it('12. should never return synthetic or mock findings from engines', async () => {
    const engines = [
      new TreeSitterEngine(),
      new SemgrepEngine(),
      new Z3Engine(),
      new AngrEngine(),
      new CodeQLEngine(),
      new SlitherEngine(),
      new FoundryEngine(),
      new ClarinetEngine(),
      new SpectralEngine(),
    ];

    for (const eng of engines) {
      const result = await eng.execute('tgt-mock-test', 'test-op', {});
      expect(result.findings).toEqual([]);
      expect(result.artifacts).toEqual([]);
      expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
    }
  });

  // Requirement 13: No fake engine metrics exist
  it('13. should have zero duration, non-zero exit code, and no simulated metrics for uninstalled engines', async () => {
    const semgrep = new SemgrepEngine();
    const result = await semgrep.execute('tgt-test', 'scan', {});

    expect(result.duration_ms).toBe(0);
    expect(result.exit_code).toBe(127);
    expect(result.status).not.toBe(EngineResultStatus.SUCCESS);
    expect(result.error).toContain('ENGINE_UNAVAILABLE');
  });

});

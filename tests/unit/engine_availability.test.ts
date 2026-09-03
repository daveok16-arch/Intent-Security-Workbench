import { describe, it, expect } from 'vitest';
import { GitSourceIntegrityEngine, SemgrepEngine, SlitherEngine, EngineRegistry, EngineAvailabilityStatus, EngineResultStatus } from '../../engines/index.js';

describe('Engine Availability & Anti-Fabrication Tests (Phase 0 & Phase 0.1 Requirements)', () => {
  it('should accurately report git engine available on host', async () => {
    const gitEngine = new GitSourceIntegrityEngine();
    const availability = await gitEngine.check_availability();
    expect(availability.status).toBe(EngineAvailabilityStatus.AVAILABLE);
    expect(availability.detected_path).toBeDefined();
  });

  it('should truthfully report uninstalled engines as NOT_INSTALLED rather than fake success', async () => {
    const semgrep = new SemgrepEngine();
    const avail = await semgrep.check_availability();
    expect(avail.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
    expect(avail.error).toContain('is not installed');
  });

  it('should produce an explicit failure EngineResult when executing an uninstalled engine', async () => {
    const semgrep = new SemgrepEngine();
    const result = await semgrep.execute('tgt-01', 'ast_rule_scan', {});
    
    expect(result.status).toBe(EngineResultStatus.UNAVAILABLE);
    expect(result.exit_code).toBe(127);
    expect(result.findings).toHaveLength(0); // Zero fake findings
    expect(result.error).toContain('ENGINE_UNAVAILABLE');
  });

  it('should truthfully report all registry statuses without fabrication', async () => {
    const registry = new EngineRegistry();
    const checks = await registry.check_all();
    
    const semgrepCheck = checks.find(c => c.engine_id === 'semgrep');
    expect(semgrepCheck?.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);

    const slitherCheck = checks.find(c => c.engine_id === 'slither');
    expect(slitherCheck?.status).toBe(EngineAvailabilityStatus.NOT_INSTALLED);
  });
});

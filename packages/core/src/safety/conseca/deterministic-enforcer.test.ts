/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, afterEach } from 'vitest';
import {
  deterministicEnforcement,
  enforcePolicyDeterministic,
} from './deterministic-enforcer.js';
import { SafetyCheckDecision } from '../protocol.js';
import type { SecurityPolicy } from './types.js';

const allowReadMain: SecurityPolicy = {
  read_file: {
    permissions: SafetyCheckDecision.ALLOW,
    constraints: "Only allow reading 'main.py'.",
    rationale: 'User asked to read main.py',
    arg_constraints: { path: String.raw`main\.py` },
  },
};

describe('deterministicEnforcement flag', () => {
  afterEach(() => {
    delete process.env['CONSECA_ENFORCER'];
  });

  it('is off unless explicitly requested, so the CLI keeps its LLM enforcer', () => {
    expect(deterministicEnforcement()).toBe(false);
    process.env['CONSECA_ENFORCER'] = 'llm';
    expect(deterministicEnforcement()).toBe(false);
  });

  it('is on for CONSECA_ENFORCER=deterministic, case-insensitively', () => {
    process.env['CONSECA_ENFORCER'] = 'Deterministic';
    expect(deterministicEnforcement()).toBe(true);
  });
});

describe('enforcePolicyDeterministic', () => {
  it('allows a call whose arguments satisfy every constraint', () => {
    const result = enforcePolicyDeterministic(allowReadMain, {
      name: 'read_file',
      args: { path: 'main.py' },
    });
    expect(result.decision).toBe(SafetyCheckDecision.ALLOW);
  });

  it('denies a tool the policy never mentions', () => {
    const result = enforcePolicyDeterministic(allowReadMain, {
      name: 'run_shell_command',
      args: { command: 'rm -rf /' },
    });
    expect(result.decision).toBe(SafetyCheckDecision.DENY);
    expect(result.reason).toContain('run_shell_command');
  });

  it('denies a missing tool name instead of failing open', () => {
    const result = enforcePolicyDeterministic(allowReadMain, {
      args: { path: 'main.py' },
    });
    expect(result.decision).toBe(SafetyCheckDecision.DENY);
  });

  it('anchors constraints so a prefix or suffix cannot smuggle a path through', () => {
    const paths = ['evil/main.py', 'main.py.bak', '../../etc/main.py'];
    // Compared as a map so a failure names the path that slipped through.
    const decisions = Object.fromEntries(
      paths.map((path) => [
        path,
        enforcePolicyDeterministic(allowReadMain, {
          name: 'read_file',
          args: { path },
        }).decision,
      ]),
    );
    expect(decisions).toEqual({
      'evil/main.py': SafetyCheckDecision.DENY,
      'main.py.bak': SafetyCheckDecision.DENY,
      '../../etc/main.py': SafetyCheckDecision.DENY,
    });
  });

  it('propagates a deny or ask_user permission without inspecting arguments', () => {
    const policy: SecurityPolicy = {
      delete_file: {
        permissions: SafetyCheckDecision.ASK_USER,
        constraints: 'Destructive.',
        rationale: 'Deletion needs confirmation',
        arg_constraints: {},
      },
    };
    const result = enforcePolicyDeterministic(policy, {
      name: 'delete_file',
      args: { path: 'anything' },
    });
    expect(result.decision).toBe(SafetyCheckDecision.ASK_USER);
  });

  it('denies when a constraint is not a usable pattern', () => {
    const policy: SecurityPolicy = {
      read_file: {
        permissions: SafetyCheckDecision.ALLOW,
        constraints: 'broken',
        rationale: '',
        arg_constraints: { path: '[unterminated' },
      },
    };
    const result = enforcePolicyDeterministic(policy, {
      name: 'read_file',
      args: { path: 'main.py' },
    });
    expect(result.decision).toBe(SafetyCheckDecision.DENY);
  });

  it('ignores constraints for arguments the call omits', () => {
    const result = enforcePolicyDeterministic(allowReadMain, {
      name: 'read_file',
      args: {},
    });
    expect(result.decision).toBe(SafetyCheckDecision.ALLOW);
  });

  it('serialises non-string arguments before matching', () => {
    const policy: SecurityPolicy = {
      write_file: {
        permissions: SafetyCheckDecision.ALLOW,
        constraints: 'Only two lines.',
        rationale: '',
        // String.raw keeps the regex escapes intact; a plain '\[' would be
        // parsed by TS as a literal '[' and turn this into a character class.
        arg_constraints: { lines: String.raw`\["a","b"\]` },
      },
    };
    expect(
      enforcePolicyDeterministic(policy, {
        name: 'write_file',
        args: { lines: ['a', 'b'] },
      }).decision,
    ).toBe(SafetyCheckDecision.ALLOW);
    expect(
      enforcePolicyDeterministic(policy, {
        name: 'write_file',
        args: { lines: ['a', 'c'] },
      }).decision,
    ).toBe(SafetyCheckDecision.DENY);
  });
});

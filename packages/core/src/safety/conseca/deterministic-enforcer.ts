/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Deterministic policy enforcement, as described in the Conseca paper.
 *
 * The shipped enforcer asks a Flash model whether a tool call complies with the
 * policy, which costs one LLM call per tool call and makes the enforcement
 * decision itself probabilistic. The paper's section 3.3 instead evaluates
 * regex constraints over the call's arguments with no model in the loop.
 *
 * This module implements that path so the two can be compared on cost and on
 * decision quality. It is opt-in: with CONSECA_ENFORCER unset the CLI keeps
 * its stock LLM enforcer.
 *
 * Unlike the LLM path, an unknown tool or an unparseable constraint denies the
 * call rather than allowing it - a policy that does not mention a tool has not
 * granted it, which is what "least privilege" means.
 */

import type { FunctionCall } from '@google/genai';
import { SafetyCheckDecision, type SafetyCheckResult } from '../protocol.js';
import type { SecurityPolicy } from './types.js';

/** True when the deterministic evaluator should replace the LLM enforcer. */
export function deterministicEnforcement(): boolean {
  return (
    (process.env['CONSECA_ENFORCER'] ?? '').toLowerCase() === 'deterministic'
  );
}

/**
 * Extra instruction given to the policy generator in deterministic mode, so
 * the free-text `constraints` field is accompanied by something machine
 * checkable. Kept out of the default prompt so the LLM-enforcer arm of the
 * comparison sees exactly the stock prompt.
 */
export const ARG_CONSTRAINTS_INSTRUCTION = `
Additionally, each policy object must include "arg_constraints": an object
mapping argument names to JavaScript-compatible regular expressions that the
argument value must fully match. Use {} when an argument is unconstrained.
Every constraint you describe in "constraints" that can be expressed as a
pattern over an argument must also appear here.
`;

function fullMatch(pattern: string, value: string): boolean {
  // Anchor so a constraint of "main\.py" cannot be satisfied by "evil/main.py".
  const anchored = new RegExp(`^(?:${pattern})$`, 's');
  return anchored.test(value);
}

export function enforcePolicyDeterministic(
  policy: SecurityPolicy,
  toolCall: FunctionCall,
): SafetyCheckResult {
  const toolName = toolCall.name;
  if (!toolName) {
    return {
      decision: SafetyCheckDecision.DENY,
      reason: 'Tool name is missing',
    };
  }

  const toolPolicy = policy[toolName];
  if (!toolPolicy) {
    return {
      decision: SafetyCheckDecision.DENY,
      reason: `No policy grants '${toolName}' for this task`,
    };
  }

  if (toolPolicy.permissions !== SafetyCheckDecision.ALLOW) {
    return {
      decision: toolPolicy.permissions,
      reason:
        toolPolicy.rationale ||
        `Policy sets '${toolName}' to ${toolPolicy.permissions}`,
    };
  }

  const constraints = toolPolicy.arg_constraints ?? {};
  const args = toolCall.args ?? {};

  for (const [argName, pattern] of Object.entries(constraints)) {
    if (!pattern) continue;
    const value = args[argName];
    if (value === undefined) continue; // absent optional argument
    const asText = typeof value === 'string' ? value : JSON.stringify(value);
    let matched: boolean;
    try {
      matched = fullMatch(pattern, asText);
    } catch {
      return {
        decision: SafetyCheckDecision.DENY,
        reason: `Constraint for '${argName}' is not a valid pattern: ${pattern}`,
      };
    }
    if (!matched) {
      return {
        decision: SafetyCheckDecision.DENY,
        reason: `Argument '${argName}' does not satisfy the policy constraint ${pattern}`,
      };
    }
  }

  return {
    decision: SafetyCheckDecision.ALLOW,
    reason: toolPolicy.rationale || 'Tool call satisfies the policy',
  };
}

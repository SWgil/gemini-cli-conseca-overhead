/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import type { SafetyCheckDecision } from '../protocol.js';

export interface ToolPolicy {
  permissions: SafetyCheckDecision;
  constraints: string;
  rationale: string;
  /**
   * Argument name -> regular expression the value must fully match.
   * Only populated in deterministic enforcement mode; the stock LLM
   * enforcer reads the free-text `constraints` instead.
   */
  arg_constraints?: Record<string, string>;
}

/**
 * A map of tool names to their specific security policies.
 */
export type SecurityPolicy = Record<string, ToolPolicy>;

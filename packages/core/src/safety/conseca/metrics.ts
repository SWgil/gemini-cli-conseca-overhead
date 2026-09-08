/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Stage-level cost instrumentation for the Conseca checker.
 *
 * The shipped telemetry events (`ConsecaPolicyGenerationEvent`,
 * `ConsecaVerdictEvent`) record *what* was decided but not what it cost, so
 * there is no way to answer how much the policy LLM adds to a turn. This
 * writes one JSONL record per policy LLM call in the same shape as the
 * Progent-side instrumentation, so the two systems can be compared directly.
 *
 * Enabled by setting CONSECA_METRICS_PATH; a no-op otherwise.
 */

import type { GenerateContentResponse } from '@google/genai';
import { appendFileSync } from 'node:fs';
import { debugLogger } from '../../utils/debugLogger.js';

/** Stages a Conseca policy LLM call can belong to. */
export type ConsecaStage = 'generate' | 'enforce';

export interface ConsecaMetricEvent {
  kind: 'policy_llm' | 'policy_parse';
  stage: ConsecaStage;
  model: string;
  seconds?: number;
  promptTokens?: number;
  completionTokens?: number;
  ok?: boolean;
  error?: string;
  tool?: string;
}

export function metricsPath(): string {
  return process.env['CONSECA_METRICS_PATH'] ?? '';
}

export function record(event: ConsecaMetricEvent): void {
  const path = metricsPath();
  if (!path) return;
  try {
    appendFileSync(
      path,
      JSON.stringify({
        ts: Date.now() / 1000,
        runTag: process.env['CONSECA_RUN_TAG'] ?? '',
        ...event,
      }) + '\n',
      'utf-8',
    );
  } catch (error) {
    // Telemetry must never break a turn.
    debugLogger.debug('[Conseca] failed to write metrics:', error);
  }
}

/**
 * Token counts as reported by the API, normalised to the field names used by
 * the metrics file. Returns zeros when the response omits usage, which some
 * backends do.
 */
export function usageOf(result: GenerateContentResponse): {
  promptTokens: number;
  completionTokens: number;
} {
  const usage = result.usageMetadata;
  return {
    promptTokens: usage?.promptTokenCount ?? 0,
    completionTokens: usage?.candidatesTokenCount ?? 0,
  };
}

/**
 * Model for a stage. Both stages default to the flash model the CLI ships
 * with, so an unset environment reproduces stock behaviour.
 */
export function stageModel(stage: ConsecaStage, fallback: string): string {
  const key =
    stage === 'generate' ? 'CONSECA_POLICY_MODEL' : 'CONSECA_ENFORCER_MODEL';
  return process.env[key] || process.env['CONSECA_MODEL'] || fallback;
}

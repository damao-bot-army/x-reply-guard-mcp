/**
 * Wakes the drafting agent (Echo) when a review ends, so it can wrap up or rewrite without being pinged.
 *
 * Configured with ECHO_WAKE_URL (https only) and an optional ECHO_WAKE_TOKEN secret, sent as
 * `Authorization: Bearer <token>`. The JSON body never contains the draft text or any credential:
 *
 *   { "event": "draft.review_result", "draft_id": "...", "result": "published" | "rejected" | "publish_failed",
 *     "draft_state": "...", "post_id"?: "...", "post_url"?: "...", "reason"?: "...", "retryable"?: boolean, "time": "..." }
 *
 * Delivery is best effort with a short timeout; the outcome is written to the audit log and never changes
 * the review result. The agent can always confirm with get_status({ draft_id }).
 */
import type { Env, Fetcher } from './types';

export type WakeResult = 'published' | 'rejected' | 'publish_failed';
export interface WakePayload {
  event: 'draft.review_result';
  draft_id: string;
  result: WakeResult;
  draft_state: string;
  post_id?: string;
  post_url?: string;
  reason?: string;
  retryable?: boolean;
  time: string;
}
const TIMEOUT_MS = 5000;

/** The configured https wake URL, or undefined when unset or not https. */
export function wakeUrl(env: Env): URL | undefined {
  const raw = (env.ECHO_WAKE_URL ?? '').trim();
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' && !url.username && !url.password ? url : undefined;
  } catch { return undefined; }
}

/** Returns a short audit summary such as "delivered (204)", "skipped: not configured" or "failed: timeout". */
export async function sendWake(env: Env, fetcher: Fetcher, payload: WakePayload): Promise<string> {
  if (!(env.ECHO_WAKE_URL ?? '').trim()) return 'skipped: not configured';
  const url = wakeUrl(env);
  if (!url) return 'skipped: ECHO_WAKE_URL must be an https URL';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (env.ECHO_WAKE_TOKEN) headers.Authorization = `Bearer ${env.ECHO_WAKE_TOKEN}`;
  try {
    const response = await fetcher(new Request(url.href, {
      method: 'POST', headers, body: JSON.stringify(payload), redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS),
    }));
    await response.body?.cancel();
    return response.ok ? `delivered (${response.status})` : `failed: HTTP ${response.status}`;
  } catch (error) {
    const name = error instanceof Error ? error.name : '';
    return name === 'TimeoutError' || name === 'AbortError' ? 'failed: timeout' : 'failed: network error';
  }
}

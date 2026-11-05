import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

export interface Env {
  GUARD_STORE: DurableObjectNamespace;
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  AUTH_PASSWORD: string;
  APPROVAL_SECRET: string;
  X_API_KEY: string;
  X_API_SECRET: string;
  X_ACCESS_TOKEN: string;
  X_ACCESS_TOKEN_SECRET: string;
  X_USER_ID: string;
  X_USERNAME: string;
  PUBLISH_MODE?: string;
  MAX_POSTS_PER_HOUR?: string;
  MAX_POSTS_PER_DAY?: string;
  DRAFT_TTL_MINUTES?: string;
  /** Cloudflare Access team domain, e.g. `myteam.cloudflareaccess.com`. Required for the review pages. */
  ACCESS_TEAM_DOMAIN?: string;
  /** Audience (AUD) tag of the Access application protecting /admin/approve/*. Required for the review pages. */
  ACCESS_AUD?: string;
  /** Local development and e2e only: `true` accepts X-Test-Access-Identity on localhost. Never set in production. */
  ACCESS_TEST_DOUBLE?: string;
  /** Optional https endpoint notified when a review ends (published / rejected / publish_failed). */
  ECHO_WAKE_URL?: string;
  /** Optional secret sent as `Authorization: Bearer <token>` to ECHO_WAKE_URL. */
  ECHO_WAKE_TOKEN?: string;
}
export type Fetcher = (request: Request) => Promise<Response>;
export interface Draft {
  id: string;
  text: string;
  hash: string;
  target?: string;
  targetInfo?: unknown;
  expires: number;
  /**
   * pending: awaiting review. rejected: sent back by the reviewer. used: reserved for sending (quota and dedupe
   * taken) with the outcome not yet recorded; if it stays so, the outcome is unknown. published: sent, post_id set.
   * publish_failed: reserved but sending failed; never retried (create a new draft). approved: legacy state from
   * the old two-step flow, no longer produced.
   */
  state: 'pending' | 'approved' | 'rejected' | 'used' | 'published' | 'publish_failed';
  risk_flags: string[];
  post_id?: string;
  /** Redacted failure summary for publish_failed. */
  failure?: string;
}
export interface Audit {
  time: string;
  action: string;
  draft_id?: string;
  target?: string;
  text_hash?: string;
  result: string;
}
export interface StoreData {
  drafts: Record<string, Draft>;
  recent: string[];
  hour: string;
  day: string;
  hourly: number;
  daily: number;
  audit: Audit[];
}

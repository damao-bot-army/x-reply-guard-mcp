export interface Env {
  GUARD_STORE: DurableObjectNamespace;
  MCP_BEARER_TOKEN: string;
  APPROVAL_SECRET: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  ACCESS_ALLOWED_EMAILS?: string;
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
}
export type Fetcher = (request: Request) => Promise<Response>;
export interface Draft {
  id: string;
  text: string;
  hash: string;
  target?: string;
  targetInfo?: unknown;
  expires: number;
  state: 'pending' | 'approved' | 'rejected' | 'used';
  risk_flags: string[];
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

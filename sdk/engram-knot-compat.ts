/**
 * Zero-dependency ESM TypeScript drop-in compatibility adapter for Weaviate Engram,
 * backed by Knot EnterpriseBrain REST endpoints:
 *   - POST /v1/context/upsert
 *   - POST /v1/context/retrieve
 *   - GET  /v1/subjects/{id}/lineage
 *   - DELETE /v1/subjects/{id}/key
 */

export const DEFAULT_KNOT_REST_URL = "https://production.connectknot.com/v1";

export type KnotCategory =
  | "fact"
  | "preference"
  | "decision"
  | "constraint"
  | "goal"
  | "project_state"
  | "person"
  | "relationship";

export interface EngramKnotCompatOptions {
  apiKey?: string;
  baseUrl?: string;
  domain?: string;
  defaultSubjectId?: string;
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

export interface MemoryAddOptions {
  content?: string;
  messages?: Array<{ role?: string; content: string }>;
  userId?: string;
  group?: string;
  topic?: string;
  entityKey?: string;
  category?: KnotCategory;
  observedAt?: string;
  supersedes?: string | null;
  idempotencyKey?: string;
  properties?: Record<string, unknown>;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface MemorySearchOptions {
  query?: string;
  userId?: string;
  group?: string;
  topic?: string;
  scopes?: string[];
  asOf?: string;
  limit?: number;
  properties?: Record<string, unknown>;
}

export interface MemoryGetOptions {
  userId?: string;
  entityKey?: string;
}

export interface MemoryDeleteOptions {
  userId?: string;
  eraseSubject?: boolean;
  entityKey?: string;
  domain?: string;
}

export interface MemoryRecord {
  id?: string;
  contextId?: string;
  context_id?: string;
  content?: string;
  statement?: string;
  category?: string;
  entityKey?: string;
  observedAt?: string;
  provenance?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface LineageResponse {
  subjectId?: string;
  items?: MemoryRecord[];
  lineage?: MemoryRecord[];
  versions?: MemoryRecord[];
  [key: string]: unknown;
}

export class EngramKnotCompatError extends Error {
  public readonly status?: number;
  public readonly code?: string;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = "EngramKnotCompatError";
    this.status = status;
    this.code = code;
  }
}

function normalizeV1Base(baseUrl?: string): string {
  const cleaned = (baseUrl ?? DEFAULT_KNOT_REST_URL).trim().replace(/\/+$/, "");
  if (!cleaned) return DEFAULT_KNOT_REST_URL;
  return cleaned.endsWith("/v1") ? cleaned : `${cleaned}/v1`;
}

function slugify(value: string, maxLen = 120): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return (slug || "memory").slice(0, maxLen).replace(/^_+|_+$/g, "") || "memory";
}

function isLuhnValid(digits: string): boolean {
  if (!/^\d{13,19}$/.test(digits) || new Set(digits).size <= 1) {
    return false;
  }
  let total = 0;
  for (let idx = 0; idx < digits.length; idx++) {
    let num = digits.charCodeAt(digits.length - 1 - idx) - 48;
    if (idx % 2 === 1) {
      num *= 2;
      if (num > 9) num -= 9;
    }
    total += num;
  }
  return total % 10 === 0;
}

function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeHighEntropySecret(val: string): boolean {
  if (val === "[REDACTED_SECRET]" || val === "[REDACTED_PAN]") return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(val)) {
    return false;
  }
  if (/^[0-9a-f]{7,40}$/.test(val) && [7, 8, 12, 40].includes(val.length)) {
    return false;
  }
  const classes =
    (/[a-z]/.test(val) ? 1 : 0) +
    (/[A-Z]/.test(val) ? 1 : 0) +
    (/[0-9]/.test(val) ? 1 : 0) +
    (/[_./+=~!$@#%^&*-]/.test(val) ? 1 : 0);
  const ent = shannonEntropy(val);
  return (ent >= 3.0 && classes >= 2) || (val.length >= 20 && ent >= 3.2);
}

function scrubText(text: string): string {
  let out = text
    .replace(
      /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
      "[REDACTED_SECRET]",
    )
    .replace(
      /\bBearer\s+eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
      "[REDACTED_SECRET]",
    )
    .replace(/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED_SECRET]")
    .replace(/\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b/g, "[REDACTED_SECRET]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED_SECRET]")
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,})\b/g, "[REDACTED_SECRET]")
    .replace(
      /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|ACCESS_KEY))\s*([:=])\s*(['"]?)([A-Za-z0-9_./+=~!$@#%^&*-]{12,})\3/gi,
      (full, key: string, sep: string, quote: string, val: string) =>
        looksLikeHighEntropySecret(val) ? `${key}${sep}${quote}[REDACTED_SECRET]${quote}` : full,
    );

  out = out.replace(/(?<![A-Za-z0-9_])(?:\d[ -]?){12,18}\d(?![A-Za-z0-9_])/g, (raw) => {
    const digits = raw.replace(/[ -]/g, "");
    return isLuhnValid(digits) ? "[REDACTED_PAN]" : raw;
  });

  return out;
}

function inferCategory(topic?: string, explicit?: KnotCategory): KnotCategory {
  if (explicit) return explicit;
  if (!topic) return "fact";
  const t = topic.trim().toLowerCase();
  if (t.includes("preference") || t === "userknowledge" || t === "user_knowledge") {
    return "preference";
  }
  if (t.includes("decision") || t === "architecture" || t === "adr") return "decision";
  if (t.includes("constraint") || t === "security" || t === "policy" || t === "rules") {
    return "constraint";
  }
  if (t.includes("goal") || t === "roadmap" || t === "objectives") return "goal";
  if (t.includes("state") || t === "status" || t === "rollout") return "project_state";
  return "fact";
}

export class EngramKnotCompatClient {
  public readonly apiKey: string;
  public readonly baseUrl: string;
  public readonly domain: string;
  public readonly defaultSubjectId: string;
  private readonly timeoutMs: number;
  private readonly extraHeaders: Record<string, string>;
  private readonly fetchFn: typeof fetch;

  public readonly memories: {
    add: (input: string | MemoryAddOptions, options?: Omit<MemoryAddOptions, "content">) => Promise<Record<string, unknown>>;
    search: (query?: string, options?: Omit<MemorySearchOptions, "query">) => Promise<Record<string, unknown>>;
    get: (memoryId: string, options?: MemoryGetOptions) => Promise<MemoryRecord | null>;
    delete: (memoryId?: string, options?: MemoryDeleteOptions) => Promise<Record<string, unknown>>;
  };

  constructor(options: EngramKnotCompatOptions = {}) {
    const envApiKey =
      typeof process !== "undefined" && process.env ? process.env.KNOT_API_KEY : undefined;
    const envBaseUrl =
      typeof process !== "undefined" && process.env ? process.env.KNOT_BASE_URL : undefined;

    const resolvedKey = options.apiKey ?? envApiKey ?? "";
    if (!resolvedKey) {
      throw new EngramKnotCompatError("Missing Knot API key. Pass apiKey or set KNOT_API_KEY.");
    }

    this.apiKey = resolvedKey;
    this.baseUrl = normalizeV1Base(options.baseUrl ?? envBaseUrl ?? DEFAULT_KNOT_REST_URL);
    this.domain = options.domain ?? "engram-compat";
    this.defaultSubjectId = options.defaultSubjectId ?? "default";
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.extraHeaders = { ...(options.headers ?? {}) };
    this.fetchFn = options.fetchImpl ?? fetch;

    this.memories = {
      add: (input, opts) => {
        const merged: MemoryAddOptions =
          typeof input === "string" ? { ...(opts ?? {}), content: input } : input;
        return this.addMemory(merged);
      },
      search: (query = "", opts = {}) => this.searchMemories({ ...opts, query }),
      get: (memoryId, opts = {}) => this.getMemory(memoryId, opts),
      delete: (memoryId, opts = {}) => this.deleteMemory(memoryId, opts),
    };
  }

  private async request<T = Record<string, unknown>>(
    method: string,
    path: string,
    payload?: unknown,
    query?: Record<string, string | undefined>,
  ): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (query) {
      const sp = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") sp.set(k, v);
      }
      const qs = sp.toString();
      if (qs) url = `${url}?${qs}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await this.fetchFn(url, {
        method,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          ...this.extraHeaders,
        },
        body: payload !== undefined ? JSON.stringify(payload) : undefined,
        signal: controller.signal,
      });

      const raw = await resp.text();
      if (!resp.ok) {
        let code: string | undefined;
        let msg = raw.slice(0, 400);
        try {
          const errObj = JSON.parse(raw) as Record<string, unknown>;
          code = (errObj.code as string | undefined) ?? (errObj.error as string | undefined);
          msg = (errObj.message as string | undefined) ?? msg;
        } catch {
          // keep raw error message
        }
        throw new EngramKnotCompatError(
          `HTTP ${resp.status} from ${method} ${url}: ${msg}`,
          resp.status,
          code,
        );
      }

      if (!raw.trim()) return {} as T;
      return JSON.parse(raw) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private async addMemory(options: MemoryAddOptions): Promise<Record<string, unknown>> {
    let text = options.content;
    if (!text && options.messages?.length) {
      text = options.messages
        .filter((m) => Boolean(m.content))
        .map((m) => `${m.role ?? "user"}: ${m.content}`.trim())
        .join("\n");
    }
    if (!text || !text.trim()) {
      throw new Error("content (or non-empty messages) is required for memories.add().");
    }

    const scrubbed = scrubText(text.trim());
    const subjectId = options.userId ?? this.defaultSubjectId;
    const domain = options.group ?? this.domain;
    const category = inferCategory(options.topic, options.category);
    const entityKey =
      options.entityKey ??
      slugify(`${options.topic ?? "general"}:${scrubbed.split(/\s+/).slice(0, 6).join(" ")}`);

    return this.request("POST", "/context/upsert", {
      subjectId,
      domain,
      category,
      entityKey,
      content: scrubbed,
      observedAt: options.observedAt ?? new Date().toISOString(),
      supersedes: options.supersedes ?? null,
      provenance: {
        source: "engram-knot-compat-ts",
        group: options.group ?? null,
        topic: options.topic ?? null,
        tags: options.tags ?? [],
        properties: options.properties ?? {},
        ...(options.idempotencyKey ? { idempotency_key: options.idempotencyKey } : {}),
        ...(options.metadata ? { metadata: options.metadata } : {}),
      },
    });
  }

  private async searchMemories(options: MemorySearchOptions): Promise<Record<string, unknown>> {
    const subjectId = options.userId ?? this.defaultSubjectId;
    const scopes = options.scopes ?? [options.group ?? this.domain];
    const body: Record<string, unknown> = {
      subjectId,
      query: options.query ?? "",
      scopes,
      limit: options.limit ?? 20,
    };
    if (options.asOf) body.asOf = options.asOf;
    if (options.topic) body.topic = options.topic;
    if (options.properties) body.properties = options.properties;
    return this.request("POST", "/context/retrieve", body);
  }

  private async getMemory(
    memoryId: string,
    options: MemoryGetOptions = {},
  ): Promise<MemoryRecord | null> {
    if (!memoryId) throw new Error("memoryId is required.");
    const subjectId = options.userId ?? this.defaultSubjectId;
    const resp = await this.getLineage(subjectId, options.entityKey, { memoryId });

    if (
      resp.id === memoryId ||
      resp.contextId === memoryId ||
      resp.context_id === memoryId
    ) {
      return resp as MemoryRecord;
    }

    for (const listKey of ["items", "lineage", "versions", "memories", "results"] as const) {
      const arr = resp[listKey];
      if (!Array.isArray(arr)) continue;
      for (const entry of arr) {
        if (!entry || typeof entry !== "object") continue;
        const rec = entry as MemoryRecord;
        const prov = (rec.provenance ?? {}) as Record<string, unknown>;
        if (
          rec.id === memoryId ||
          rec.contextId === memoryId ||
          rec.context_id === memoryId ||
          prov.source_memory_id === memoryId
        ) {
          return rec;
        }
      }
    }
    return null;
  }

  private async deleteMemory(
    memoryId?: string,
    options: MemoryDeleteOptions = {},
  ): Promise<Record<string, unknown>> {
    const subjectId = options.userId ?? this.defaultSubjectId;
    if (options.eraseSubject || !memoryId || memoryId === subjectId) {
      return this.eraseUserSubject(subjectId);
    }

    const result = await this.request("POST", "/context/upsert", {
      subjectId,
      domain: options.domain ?? this.domain,
      category: "project_state",
      entityKey: options.entityKey ?? `retracted:${memoryId}`,
      content: `[TOMBSTONED] Memory ${memoryId} retracted via compatibility adapter.`,
      observedAt: new Date().toISOString(),
      supersedes: memoryId,
      provenance: {
        source: "engram-knot-compat-ts",
        action: "tombstone",
        retracted_memory_id: memoryId,
      },
    });
    return { status: "tombstoned", superseded_id: memoryId, result };
  }

  public async eraseUserSubject(userId: string): Promise<Record<string, unknown>> {
    if (!userId) throw new Error("userId is required for eraseUserSubject().");
    return this.request("DELETE", `/subjects/${encodeURIComponent(userId)}/key`);
  }

  public async getLineage(
    userId: string,
    entityKey?: string,
    extraQuery?: Record<string, string | undefined>,
  ): Promise<LineageResponse> {
    if (!userId) throw new Error("userId is required for getLineage().");
    return this.request<LineageResponse>(
      "GET",
      `/subjects/${encodeURIComponent(userId)}/lineage`,
      undefined,
      {
        ...(extraQuery ?? {}),
        ...(entityKey ? { entityKey } : {}),
      },
    );
  }
}

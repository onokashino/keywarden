// Сообщения между content script / popup и background. Логика в Rust (WASM) и в демоне.

export type FieldInfo = {
  index: number;
  form: number;
  type: string;
  name: string;
  id: string;
  autocomplete: string;
  placeholder: string;
  label: string;
  visible: boolean;
  maxlength: number | null;
};

export type LoginForm = {
  form: number;
  username: number | null;
  password: number | null;
  new_passwords: number[];
  otp: number | null;
};

export type Login = { id: string; title: string; username: string; group: string; has_otp: boolean; url?: string; kind?: string };

export type Folder = { id: string; name: string; depth: number; count: number };
export type Filter = { group?: string; kind?: string; tag?: string };

export type Item = {
  id: string;
  title: string;
  username: string;
  url: string;
  group: string;
  has_password: boolean;
  /// [код, осталось секунд, период]
  totp: [string, number, number] | null;
  kind?: string;
  /// публичные адреса кошелька: [подпись, адрес]
  addresses?: [string, string][];
};

export type Status = { connected: boolean; associated: boolean; locked: boolean; error?: string };

export type PendingSave = { site: string; username: string; password: string; state: 'new' | 'changed'; id?: string };

export type Msg =
  | { type: 'status' }
  | { type: 'associate' }
  | { type: 'classify'; fields: FieldInfo[] }
  | { type: 'logins'; tabId?: number }
  | { type: 'fill'; id: string; tabId?: number }
  | { type: 'totp'; id: string; tabId?: number }
  | { type: 'generate' }
  | { type: 'generateWith'; options: GenOptions }
  | { type: 'fillNew'; password: string; tabId?: number }
  | { type: 'submitted'; username: string; password: string }
  | { type: 'pendingSave'; tabId?: number }
  | { type: 'save'; accept: boolean; tabId?: number }
  | { type: 'neverSave'; tabId?: number }
  | { type: 'autoOtp' }
  | { type: 'search'; query: string; filter?: Filter }
  | { type: 'facets' }
  | { type: 'lock' }
  | { type: 'create'; title: string; username: string; password: string; url: string }
  | { type: 'item'; id: string }
  | { type: 'copy'; id: string; field: 'username' | 'password' | 'totp' }
  | { type: 'openUnlock' }
  | { type: 'passkeyCreate'; options: unknown }
  | { type: 'passkeyList'; options: unknown }
  | { type: 'passkeyGet'; options: unknown; id: string };

/// Сообщения background → content script
export type ContentMsg =
  | { type: 'triggerFill' }
  | { type: 'fillWith'; username: string; password: string }
  | { type: 'fillOtp'; code: string }
  | { type: 'fillNew'; password: string }
  | { type: 'togglePanel' }
  | { type: 'showSave' };

/// Параметры генератора как в keywarden-core::generator (mode: password | passphrase)
export type GenOptions =
  | { mode: 'password'; length: number; lower: boolean; upper: boolean; digits: boolean; symbols: boolean; exclude_ambiguous: boolean }
  | { mode: 'passphrase'; words: number; separator: string; capitalize: boolean; number: boolean };

export type Reply<T> = { ok: true; value: T } | { ok: false; code: string; error: string };

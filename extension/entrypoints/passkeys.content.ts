// Ключи доступа: перехват navigator.credentials.create/get в мире страницы (MAIN).
// Здесь нет ни ключей, ни решений: опции уходят изолированному content script → background →
// keywardend, который проверяет rpId по адресу вкладки (а не по словам страницы) и спрашивает
// пользователя. Если Keywarden не может или пользователь отказался, работает обычный WebAuthn
// браузера (аппаратные ключи, телефон).
export default defineContentScript({
  matches: ['https://*/*', 'http://localhost/*', 'http://127.0.0.1/*'],
  world: 'MAIN',
  runAt: 'document_start',
  main() {
    const creds = navigator.credentials;
    if (!creds || typeof window.PublicKeyCredential === 'undefined') return;
    const origCreate = creds.create.bind(creds);
    const origGet = creds.get.bind(creds);

    const toB64u = (buf: ArrayBuffer | ArrayBufferView) => {
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      let s = '';
      for (const b of bytes) s += String.fromCharCode(b);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const fromB64u = (s: string): ArrayBuffer => {
      const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    };
    // буферы → base64url, всё остальное как есть (JSON для передачи)
    const serialize = (v: any): any => {
      if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return toB64u(v as any);
      if (Array.isArray(v)) return v.map(serialize);
      if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x !== 'function').map(([k, x]) => [k, serialize(x)]));
      return v;
    };

    const pending = new Map<string, (r: any) => void>();
    window.addEventListener('message', (e) => {
      if (e.source !== window || e.data?.kw !== 'passkey-result') return;
      pending.get(e.data.id)?.(e.data);
      pending.delete(e.data.id);
    });
    const ask = (kind: 'create' | 'get', options: any) =>
      new Promise<any>((resolve) => {
        const id = crypto.randomUUID();
        pending.set(id, resolve);
        window.postMessage({ kw: 'passkey-request', id, kind, options }, location.origin);
      });

    const toCredential = (j: any, kind: 'create' | 'get') => {
      const r = j.response;
      const response: any =
        kind === 'create'
          ? {
              clientDataJSON: fromB64u(r.clientDataJSON),
              attestationObject: fromB64u(r.attestationObject),
              getTransports: () => r.transports ?? [],
              getAuthenticatorData: () => fromB64u(r.authenticatorData),
              getPublicKey: () => fromB64u(r.publicKey),
              getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
            }
          : {
              clientDataJSON: fromB64u(r.clientDataJSON),
              authenticatorData: fromB64u(r.authenticatorData),
              signature: fromB64u(r.signature),
              userHandle: r.userHandle ? fromB64u(r.userHandle) : null,
            };
      Object.setPrototypeOf(response, kind === 'create' ? AuthenticatorAttestationResponse.prototype : AuthenticatorAssertionResponse.prototype);
      const cred: any = {
        id: j.id,
        rawId: fromB64u(j.rawId),
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response,
        getClientExtensionResults: () => ({}),
        toJSON: () => j,
      };
      Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
      return cred;
    };

    creds.create = async function (options?: CredentialCreationOptions) {
      if (!options?.publicKey) return origCreate(options);
      const r = await ask('create', serialize(options.publicKey));
      if (r.fallback) return origCreate(options);
      if (!r.ok) throw new DOMException(r.error, r.name ?? 'NotAllowedError');
      return toCredential(r.credential, 'create');
    };

    creds.get = async function (options?: CredentialRequestOptions) {
      // условный UI (подсказки в поле логина) оставляем браузеру
      if (!options?.publicKey || options.mediation === 'conditional') return origGet(options);
      const r = await ask('get', serialize(options.publicKey));
      if (r.fallback) return origGet(options);
      if (!r.ok) throw new DOMException(r.error, r.name ?? 'NotAllowedError');
      return toCredential(r.credential, 'get');
    };
  },
});

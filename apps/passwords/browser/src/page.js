// Runs in the page's own world, only when passkeys are turned on in Nyx Passwords:
// `navigator.credentials.create` and `.get` for public keys go to Nyx Passwords first.
// The request passes through the content script to the extension, which builds the
// client data from the frame's real origin and asks the user in its own window. When
// the user picks the browser instead, or nothing is saved, the browser's own runs.

(() => {
  const credentials = navigator.credentials;
  if (!credentials || window.__nyxWebAuthn) return;
  window.__nyxWebAuthn = true;
  const originalGet = credentials.get.bind(credentials);
  const originalCreate = credentials.create.bind(credentials);

  const b64url = (buffer) => {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const bytes = (text) => {
    const s = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0)).buffer;
  };

  // The content script loads after this one (once the page is ready): a request it
  // doesn't acknowledge goes to the browser's own.
  let next = 0;
  function ask(kind, options) {
    const id = `${Date.now()}-${next++}`;
    return new Promise((resolve) => {
      const unheard = setTimeout(() => done({ fallback: true }), 500);
      const listen = (e) => {
        if (e.source !== window || e.data?.id !== id) return;
        if (e.data.nyx === "webauthn-ack") clearTimeout(unheard);
        if (e.data.nyx === "webauthn-reply") done(e.data.answer);
      };
      const done = (answer) => {
        clearTimeout(unheard);
        window.removeEventListener("message", listen);
        resolve(answer);
      };
      window.addEventListener("message", listen);
      window.postMessage({ nyx: "webauthn", id, kind, options }, location.origin);
    });
  }

  // `getPublicKey()` is SubjectPublicKeyInfo; Passwords gives the COSE key (a P-256 map
  // of fixed layout: x at 10, y at 45).
  const SPKI_P256 = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04];
  function spki(cose) {
    if (!cose) return null;
    const k = new Uint8Array(bytes(cose));
    if (k.length !== 77 || k[9] !== 0x20 || k[44] !== 0x20) return null;
    const out = new Uint8Array(SPKI_P256.length + 64);
    out.set(SPKI_P256);
    out.set(k.subarray(10, 42), SPKI_P256.length);
    out.set(k.subarray(45, 77), SPKI_P256.length + 32);
    return out.buffer;
  }

  function credential(kind, c) {
    const rawId = bytes(c.id);
    const clientDataJSON = bytes(c.clientDataJSON);
    const response =
      kind === "get"
        ? Object.setPrototypeOf(
            { clientDataJSON, authenticatorData: bytes(c.authenticatorData), signature: bytes(c.signature), userHandle: c.userHandle ? bytes(c.userHandle) : null },
            AuthenticatorAssertionResponse.prototype,
          )
        : Object.setPrototypeOf(
            {
              clientDataJSON,
              attestationObject: bytes(c.attestationObject),
              getTransports: () => ["internal", "hybrid"],
              getAuthenticatorData: () => bytes(c.authenticatorData),
              getPublicKey: () => spki(c.publicKey),
              getPublicKeyAlgorithm: () => c.algorithm,
            },
            AuthenticatorAttestationResponse.prototype,
          );
    const out = {
      id: c.id,
      rawId,
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: c.id,
        rawId: c.id,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
        response:
          kind === "get"
            ? { clientDataJSON: c.clientDataJSON, authenticatorData: c.authenticatorData, signature: c.signature, userHandle: c.userHandle }
            : {
                clientDataJSON: c.clientDataJSON, attestationObject: c.attestationObject, transports: ["internal", "hybrid"],
                authenticatorData: c.authenticatorData, publicKeyAlgorithm: c.algorithm,
                publicKey: spki(c.publicKey) && b64url(spki(c.publicKey)),
              },
      }),
    };
    return Object.setPrototypeOf(out, PublicKeyCredential.prototype);
  }

  // Only what the extension needs, as text: the rest of the request stays here.
  function plain(kind, pk) {
    const ids = (list) => (list ?? []).map((c) => ({ id: b64url(c.id), type: c.type }));
    return kind === "get"
      ? { challenge: b64url(pk.challenge), rpId: pk.rpId, allowCredentials: ids(pk.allowCredentials), userVerification: pk.userVerification }
      : {
          challenge: b64url(pk.challenge),
          rp: { id: pk.rp?.id, name: pk.rp?.name },
          user: { id: b64url(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
          excludeCredentials: ids(pk.excludeCredentials),
          authenticatorSelection: pk.authenticatorSelection ?? {},
          supportsES256: (pk.pubKeyCredParams ?? []).some((p) => p.alg === -7),
        };
  }

  async function handle(kind, options, original) {
    const pk = options?.publicKey;
    // Autofill-style requests and sites that don't take ES256 stay with the browser.
    if (!pk || options.mediation === "conditional" || (kind === "create" && !(pk.pubKeyCredParams ?? []).some((p) => p.alg === -7))) {
      return original(options);
    }
    const answer = await ask(kind, plain(kind, pk));
    if (answer?.credential) return credential(kind, answer.credential);
    if (answer?.fallback) return original(options);
    throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
  }

  credentials.get = (options) => handle("get", options, originalGet);
  credentials.create = (options) => handle("create", options, originalCreate);
})();

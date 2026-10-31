import { Injectable } from '@angular/core';
import {
  CompactEncrypt,
  JWK,
  SignJWT,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  importJWK,
} from 'jose';

export interface JweDecomposto {
  protectedHeader: Record<string, unknown>;
  partes: { nome: string; valor: string; bytes: number }[];
}

export interface TokenAninhado {
  jws: string;
  jwsHeader: Record<string, unknown>;
  jwsPayload: Record<string, unknown>;
  jwe: string;
  jweDecomposto: JweDecomposto;
}

export interface Laudo {
  paciente_id: string;
  diagnostico: string;
  prescricao: string;
}

const DB = 'portal-medico';
const STORE = 'chaves';
const KID = 'medico-es256-1';

@Injectable({ providedIn: 'root' })
export class CryptoService {
  // ---- armazenamento do par ES256 do médico (privada não-extraível, em IndexedDB) ----

  private abrirDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async ler(sub: string): Promise<CryptoKeyPair | undefined> {
    const db = await this.abrirDb();
    return new Promise((resolve, reject) => {
      const r = db.transaction(STORE).objectStore(STORE).get(sub);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  private async gravar(sub: string, par: CryptoKeyPair): Promise<void> {
    const db = await this.abrirDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(par, sub);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  private gerarPar(extractable = false): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, extractable, [
      'sign',
      'verify',
    ]);
  }

  async temChave(sub: string): Promise<boolean> {
    return !!(await this.ler(sub));
  }

  /** Gera (ou recria) o par ES256 do médico e devolve a JWK pública. */
  async gerarChaveMedico(sub: string): Promise<JWK> {
    const par = await this.gerarPar();
    await this.gravar(sub, par);
    return this.jwkPublica(par);
  }

  async chavePublicaMedico(sub: string): Promise<JWK | null> {
    const par = await this.ler(sub);
    return par ? this.jwkPublica(par) : null;
  }

  private async jwkPublica(par: CryptoKeyPair): Promise<JWK> {
    return { ...(await exportJWK(par.publicKey)), kid: KID, alg: 'ES256', use: 'sig' };
  }

  // ---- Nested JWT: Sign-then-Encrypt ----

  /**
   * Passo 1: JWS ES256 com a chave privada do médico.
   * Passo 2: JWE (ECDH-ES P-256 + A128GCM, cty=JWT) tendo o JWS como plaintext.
   * O 'epk' (chave efêmera) é gerado a cada cifragem pela biblioteca.
   */
  async criarTokenAninhado(
    sub: string,
    laudo: Laudo,
    chaveServidor: JWK,
    opcoes: { chaveAssinatura?: CryptoKey } = {},
  ): Promise<TokenAninhado> {
    const chave = opcoes.chaveAssinatura ?? (await this.ler(sub))?.privateKey;
    if (!chave) throw new Error('Gere a chave de assinatura do médico primeiro.');

    const jws = await new SignJWT({ ...laudo })
      .setProtectedHeader({ alg: 'ES256', kid: KID, typ: 'JWT' })
      .setSubject(sub)
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(chave);

    const serverKey = await importJWK(chaveServidor, 'ECDH-ES');
    const jwe = await new CompactEncrypt(new TextEncoder().encode(jws))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', cty: 'JWT' })
      .encrypt(serverKey);

    return {
      jws,
      jwsHeader: decodeProtectedHeader(jws) as Record<string, unknown>,
      jwsPayload: decodeJwt(jws) as Record<string, unknown>,
      jwe,
      jweDecomposto: this.decomporJwe(jwe),
    };
  }

  /** Chave ES256 descartável, usada para simular um atacante que forja o laudo. */
  async chaveDeAtacante(): Promise<CryptoKey> {
    return (await this.gerarPar()).privateKey;
  }

  decomporJwe(jwe: string): JweDecomposto {
    const [h, ek, iv, ct, tag] = jwe.split('.');
    const bytes = (b64: string) => Math.floor((b64.length * 3) / 4);
    return {
      protectedHeader: decodeProtectedHeader(jwe) as Record<string, unknown>,
      partes: [
        { nome: '1. Protected Header', valor: h, bytes: bytes(h) },
        { nome: '2. Encrypted Key (vazio em ECDH-ES direto)', valor: ek, bytes: bytes(ek) },
        { nome: '3. IV', valor: iv, bytes: bytes(iv) },
        { nome: '4. Ciphertext', valor: ct, bytes: bytes(ct) },
        { nome: '5. Authentication Tag', valor: tag, bytes: bytes(tag) },
      ],
    };
  }

  decodificarAccessToken(token: string): { header: unknown; payload: unknown } {
    return { header: decodeProtectedHeader(token), payload: decodeJwt(token) };
  }
}

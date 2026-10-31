import { Injectable, signal } from '@angular/core';
import Keycloak from 'keycloak-js';
import { CONFIG } from './config';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly kc = new Keycloak({
    url: CONFIG.keycloak.url,
    realm: CONFIG.keycloak.realm,
    clientId: CONFIG.keycloak.clientId,
  });

  readonly autenticado = signal(false);
  readonly usuario = signal<string | null>(null);
  readonly sub = signal<string | null>(null);

  async init(): Promise<void> {
    const ok = await this.kc.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    });
    this.autenticado.set(ok);
    this.usuario.set(this.kc.tokenParsed?.['preferred_username'] ?? null);
    this.sub.set(this.kc.tokenParsed?.sub ?? null);
  }

  login(): Promise<void> {
    return this.kc.login();
  }

  logout(): Promise<void> {
    return this.kc.logout({ redirectUri: window.location.origin });
  }

  /** Access token (JWS RS256 emitido pelo Keycloak), renovado se estiver perto de expirar. */
  async token(): Promise<string> {
    await this.kc.updateToken(30);
    return this.kc.token!;
  }
}

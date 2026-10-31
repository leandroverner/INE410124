import { Injectable } from '@angular/core';
import { JWK } from 'jose';
import { AuthService } from './auth.service';
import { CONFIG } from './config';

export interface Resposta {
  status: number;
  corpo: unknown;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private auth: AuthService) {}

  async chaveServidor(): Promise<JWK> {
    const r = await fetch(`${CONFIG.apiUrl}/api/chave-publica`);
    return (await r.json()).keys[0];
  }

  async registrarChaveMedico(jwk: JWK): Promise<Resposta> {
    return this.enviar('PUT', '/api/medico/chave-publica', 'application/json', JSON.stringify(jwk));
  }

  async enviarProntuario(jwe: string): Promise<Resposta> {
    return this.enviar('POST', '/api/prontuarios', 'application/jose', jwe);
  }

  async listarProntuarios(): Promise<Resposta> {
    return this.enviar('GET', '/api/prontuarios');
  }

  private async enviar(
    method: string,
    path: string,
    contentType?: string,
    body?: string,
  ): Promise<Resposta> {
    const headers: Record<string, string> = { Authorization: `Bearer ${await this.auth.token()}` };
    if (contentType) headers['Content-Type'] = contentType;
    const r = await fetch(`${CONFIG.apiUrl}${path}`, { method, headers, body });
    const texto = await r.text();
    let corpo: unknown = texto;
    try {
      corpo = JSON.parse(texto);
    } catch {
      /* resposta não-JSON */
    }
    return { status: r.status, corpo };
  }
}

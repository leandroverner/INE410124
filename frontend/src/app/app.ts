import { JsonPipe } from '@angular/common';
import { Component, OnInit, signal } from '@angular/core';
import { JWK } from 'jose';
import { ApiService, Resposta } from './api.service';
import { AuthService } from './auth.service';
import { CryptoService, Laudo, TokenAninhado } from './crypto.service';

@Component({
  imports: [JsonPipe],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App implements OnInit {
  protected readonly accessToken = signal<{ header: unknown; payload: unknown } | null>(null);
  protected readonly chaveServidor = signal<JWK | null>(null);
  protected readonly chaveMedico = signal<JWK | null>(null);
  protected readonly chaveRegistrada = signal<Resposta | null>(null);

  protected readonly laudo = signal<Laudo>({
    paciente_id: 'P-1011',
    diagnostico: 'Reação alérgica a frutos do mar',
    prescricao: 'Loratadina 10mg, 4x ao dia',
  });
  protected readonly tokenAninhado = signal<TokenAninhado | null>(null);
  protected readonly resposta = signal<Resposta | null>(null);
  protected readonly prontuarios = signal<Resposta | null>(null);
  protected readonly erro = signal<string | null>(null);
  protected readonly ocupado = signal(false);

  constructor(
    protected readonly auth: AuthService,
    private readonly crypto: CryptoService,
    private readonly api: ApiService,
  ) {}

  async ngOnInit(): Promise<void> {
    await this.executar(async () => {
      await this.auth.init();
      this.chaveServidor.set(await this.api.chaveServidor());
      if (this.auth.autenticado()) {
        this.accessToken.set(this.crypto.decodificarAccessToken(await this.auth.token()));
        this.chaveMedico.set(await this.crypto.chavePublicaMedico(this.auth.sub()!));
      }
    });
  }

  protected atualizar(campo: keyof Laudo, ev: Event): void {
    this.laudo.update((l) => ({ ...l, [campo]: (ev.target as HTMLInputElement).value }));
  }

  protected gerarChave(): Promise<void> {
    return this.executar(async () => {
      this.chaveMedico.set(await this.crypto.gerarChaveMedico(this.auth.sub()!));
      this.chaveRegistrada.set(null);
    });
  }

  protected registrarChave(): Promise<void> {
    return this.executar(async () => {
      this.chaveRegistrada.set(await this.api.registrarChaveMedico(this.chaveMedico()!));
    });
  }

  protected enviar(atacante = false): Promise<void> {
    return this.executar(async () => {
      const chaveAssinatura = atacante ? await this.crypto.chaveDeAtacante() : undefined;
      const token = await this.crypto.criarTokenAninhado(
        this.auth.sub()!,
        this.laudo(),
        this.chaveServidor()!,
        { chaveAssinatura },
      );
      this.tokenAninhado.set(token);
      this.resposta.set(await this.api.enviarProntuario(token.jwe));
    });
  }

  protected reenviar(): Promise<void> {
    return this.executar(async () => {
      this.resposta.set(await this.api.enviarProntuario(this.tokenAninhado()!.jwe));
    });
  }

  protected listar(): Promise<void> {
    return this.executar(async () => {
      this.prontuarios.set(await this.api.listarProntuarios());
    });
  }

  private async executar(acao: () => Promise<void>): Promise<void> {
    this.ocupado.set(true);
    this.erro.set(null);
    try {
      await acao();
    } catch (e) {
      this.erro.set(e instanceof Error ? e.message : String(e));
    } finally {
      this.ocupado.set(false);
    }
  }
}

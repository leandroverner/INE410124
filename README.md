# Mini Aplicação Segura de Prontuários Médicos

Atividade 5 — Segurança: Web, Identidades e Nuvem (INE410124) · PPGCC/UFSC

Portal do Médico (Angular) → Servidor de Prontuários (Spring Boot) com autenticação OIDC (Keycloak),
assinatura **JWS ES256**, acordo de chaves **ECDH-ES (P-256)** e cifragem **JWE**, formando um
**Nested JWT (sign-then-encrypt)**.

## Arquitetura

```
 Portal Médico (Angular, :4200)      Keycloak (:8080)         Servidor de Prontuários (Spring Boot, :8081)
          |                                |                                  |
          |-- 1. login OIDC (code+PKCE) -->|                                  |
          |<-- 2. access token (RS256) ----|                                  |
          |-- GET /api/chave-publica ------------------------------------->  |  chave estática EC P-256 do servidor (PB)
          |-- PUT /api/medico/chave-publica (Bearer) ------------------------>|  guarda a pública ES256 do médico
          |                                |<-- Admin API: atributo do usuário|  (âncora de confiança = Keycloak)
          |-- 3. JWS = ES256(laudo) com a privada do médico                   |
          |-- 4. JWE = ECDH-ES(epk efêmero, PB) + A128GCM, cty=JWT, plaintext = JWS
          |-- POST /api/prontuarios (Bearer + application/jose) ------------->|
          |                                |   decifra com nB + epk (K = nB·PA)
          |                                |   valida o JWS com a pública do médico
          |<-- 201 Aceito / 422 Rejeitado --------------------------------- |
```

| Requisito do roteiro | Onde está |
|---|---|
| Keycloak (Realm, Client, usuário) | `keycloak/Telemedicina-Realm.json` (importado no start) |
| Integração OIDC | `frontend/src/app/auth.service.ts` (keycloak-js, PKCE S256); backend como *resource server* (`SecurityConfig`) |
| JWS ES256 | `frontend/src/app/crypto.service.ts` (`criarTokenAninhado`); verificação em `NestedJwtService.verificarAssinatura` |
| ECDH-ES P-256 + `epk` | cifragem no `crypto.service.ts`; decifragem em `NestedJwtService.decifrar` (`ECDHDecrypter`) |
| JWE 5 partes, `cty: JWT` | `crypto.service.ts` e validação do header em `NestedJwtService` |

Detalhes de projeto:

- **Chave do médico:** par ES256 gerado no navegador, com a privada **não extraível** (WebCrypto + IndexedDB).
  Só a pública é enviada; o backend a grava como atributo `chave_publica` do usuário no Keycloak (Admin API,
  client `prontuarios-server`).
- **Chave do servidor:** par EC P-256 estático (`nB`, `PB`), gerado na primeira execução e persistido em `keys/`
  (volume Docker `chave-servidor`).
- **ECDH-ES direto:** a parte *Encrypted Key* do JWE é vazia (`a..b.c.d`); a CEK vem do Concat KDF (RFC 7518 §4.6).
- **Validações no `POST /api/prontuarios`:** `alg=ECDH-ES`, `enc` A128GCM/A256GCM, `cty=JWT`, `epk` em P-256;
  JWS com `alg=ES256`; `sub` do laudo igual ao do access token; `iat`/`exp` válidos; `jti` único (anti-replay).

## Como executar (Docker)

Requisitos: Docker Desktop (ou Docker Engine + Compose).

```bash
docker compose up -d --build
```

Aguarde ~30 s (o Keycloak é o mais lento) e acesse:

| Serviço | URL | Credenciais |
|---|---|---|
| Portal do Médico | http://localhost:4200 | `dr.silva` / `silva123` |
| Keycloak (admin) | http://localhost:8080 | `admin` / `admin` |
| API de Prontuários | http://localhost:8081 | — |

Roteiro de uso no portal: **Entrar com Keycloak** → **Gerar par ES256** → **Registrar pública no Keycloak** →
**Assinar, cifrar e enviar** (esperado: `201`).
Os botões *Simular atacante* (laudo assinado com outra chave) e *Reenviar mesmo JWE* (replay) devem retornar `422`.

Para parar e limpar tudo (inclusive a chave do servidor): `docker compose down -v`.

## Como executar em modo desenvolvimento

Suba só o Keycloak e rode os demais localmente:

```bash
docker compose up -d keycloak

# backend (Java 25 + Maven)
cd backend && mvn spring-boot:run          # http://localhost:8081

# frontend (Node 24; o Angular 22 exige Node >= 22.22.3)
cd frontend && nvm use && npm install && npx ng serve   # http://localhost:4200
```

## Testes

```bash
cd backend && mvn test
```

Cobrem o Nested JWT ponta a ponta: laudo válido (JWE com 5 partes e parte 2 vazia), requisição sem access token,
assinatura de outra chave (simula MiTM), replay, laudo expirado e JWE adulterado.

## Evidências para o relatório

- **Keycloak:** `docker ps` e o console em http://localhost:8080 (Realm, Clients `portal-medico-app` e `prontuarios-server`,
  usuário `dr.silva` e o atributo `chave_publica` após o registro).
- **Estrutura dos tokens:** o portal exibe o JWS (3 partes), o JWE (5 partes) e o header com `alg`, `enc`, `cty` e `epk`.
- **Tráfego de rede:** DevTools → *Network* → `POST /api/prontuarios` (corpo `application/jose` opaco), ou
  `sudo tcpdump -i lo0 -A port 8081`. JWK Set do Keycloak: `http://localhost:8080/realms/Telemedicina-Realm/protocol/openid-connect/certs`.

## Estrutura

```
docker-compose.yml          Keycloak + backend + frontend
keycloak/                   realm importável (client, usuário, client de serviço)
backend/                    Spring Boot 4 / Java 25 (Nimbus JOSE + JWT)
frontend/                   Angular 22 (jose + keycloak-js)
```

## Observações e simplificações

- Keycloak em `start-dev` (HTTP, H2 em memória): adequado só para a atividade. Em produção, usar HTTPS e banco externo.
- Prontuários e `jti` ficam em memória; o secret `prontuarios-server-secret` e as senhas são de demonstração.
- O `sslRequired: none` do realm e o `KEYCLOAK_ISSUER` com `localhost` existem apenas para o ambiente local.

<p align="center">
  <img src="assets/logo_scr.png" alt="ScR Community" width="180" />
</p>

# DK License API

API que sustenta todo o sistema de licenciamento da **ScR Community**: quem emite, valida e controla as licenças dos produtos FiveM por trás do [bot do Discord](https://github.com/FranklinDKz/bot_license) e do painel de vendas.

Feita com [Fastify](https://fastify.dev/) + MySQL (Aiven), sem ORM — SQL direto, multi-organização desde a raiz.

## O que ela faz

- **Autenticação administrativa** com JWT e sessão controlada (`/api/v1/auth`).
- **Painel administrativo** (`/api/v1/admin/*`): aprovação/recusa de licenças, gestão de produtos, clientes, usuários com papéis (`root`, `owner`, `admin`, `support`, `reseller`), bloqueio por IP/Discord, auditoria e sessões ativas.
- **Integração com o bot do Discord** (`/api/v1/service/*`): fila de solicitações de licença, trocas de IP, concessão de cargo por produto.
- **Validação client-side FiveM** (`/api/v1/fivem/*`): ativação, heartbeat e desativação de licença direto do resource do servidor, com rate limit por IP.
- **Compatibilidade de banco automática**: ao subir, a API confere e aplica ajustes de schema que ainda não existem (novas colunas, tabela de concessão de cargo), sem precisar rodar migration manual.

## Arquitetura

```
src/
├── server.js              # bootstrap do Fastify, CORS, headers de segurança, healthcheck
├── lib/
│   ├── config.js           # leitura e validação das variáveis de ambiente
│   ├── db.js                # pool de conexão MySQL
│   ├── security.js          # hashing, pepper de licença, JWT
│   └── rate-limit.js        # rate limit em memória por chave
├── middleware/
│   └── auth.js               # guarda de rotas admin (JWT + papéis)
├── routes/
│   ├── auth.js, admin.js, service.js, fivem.js
└── services/
    ├── bootstrap.js         # cria o usuário root na primeira execução
    ├── licenses.js          # regras de ativação/heartbeat/desativação
    └── audit.js
```

## Variáveis de ambiente

Veja o `.env` (já versionado neste repositório privado) para a lista completa. Os grupos principais:

- `DB_*` — conexão MySQL (testado com Aiven, TLS via `DB_SSL_CA_BASE64`).
- `JWT_SECRET` / `LICENSE_PEPPER` / `BOT_SERVICE_TOKEN` — segredos de assinatura e proteção das chaves de licença. **Gere valores fortes e não troque `LICENSE_PEPPER` depois de emitir licenças** — isso invalida todas as chaves existentes.
- `ROOT_*` — conta administrativa criada automaticamente no primeiro boot.
- `PANEL_ORIGIN` — origem liberada por CORS para o painel administrativo.
- `*_RATE_LIMIT*` — limites de requisição para login e endpoints do FiveM.

## Como rodar

```bash
npm install
npm start
```

Desenvolvimento com reinício automático:

```bash
npm run dev
```

## Deploy no Render

O `render.yaml` já está pronto como [Blueprint](https://render.com/docs/blueprint-spec): build com `npm ci`, start com `npm start`, healthcheck em `/health`, deploy automático a cada push, e a lista completa de variáveis de ambiente já declarada (algumas com valor fixo, outras que o Render pede para você preencher, e os três segredos gerados automaticamente).

1. No Render, **New > Blueprint** e aponte para este repositório.
2. O Render vai pedir os campos marcados como pendentes: `PANEL_ORIGIN`, `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_SSL_CA_BASE64`, `ROOT_EMAIL`, `ROOT_PASSWORD`, `ROOT_ORG_NAME` e `DEFAULT_DISCORD_PRODUCT_ROLE_ID`.
3. `DB_SSL_CA_BASE64` é o `ca.pem` da instância Aiven em base64 numa linha só:
   ```bash
   base64 -w0 ca.pem
   ```
   (no PowerShell: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("ca.pem"))`)
4. `JWT_SECRET`, `BOT_SERVICE_TOKEN` e `LICENSE_PEPPER` são gerados automaticamente pelo Render — não precisa preencher.
5. **Não é necessário configurar `API_PUBLIC_URL`**: o código já usa `RENDER_EXTERNAL_URL`, que o Render injeta sozinho em todo serviço.
6. O banco (schema, tabelas) precisa já existir antes do primeiro boot — esta API só aplica ajustes incrementais (`ALTER TABLE`), não cria o schema do zero.

Depois do primeiro deploy, qualquer push na branch principal atualiza o serviço automaticamente.

## Segurança

- Senhas com `bcryptjs`, chaves de licença protegidas por pepper dedicado.
- Sessões administrativas com JWT + expiração configurável.
- Rate limit por IP em login e nos endpoints usados pelo client FiveM.
- Cabeçalhos de segurança (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, CSP básica via `Permissions-Policy`) aplicados globalmente.
- CORS restrito à origem configurada em `PANEL_ORIGIN`.

## Projetos relacionados

- [bot_license](https://github.com/FranklinDKz/bot_license) — bot de Discord que consome esta API.
- [dk_store-scr](https://github.com/FranklinDKz/dk_store-scr) — loja/painel que compartilha o mesmo ecossistema ScR.

## Autor

Feito por **Franklin (DK RP)** para a ScR Community.

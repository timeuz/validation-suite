# Validation Suite

API unificada em **FastAPI** com três módulos independentes para auditoria de segurança de URLs, verificação de e-mails e extração de conteúdo (web e PDF) com contagem de tokens. Utiliza **Redis** para cache e feeds de ameaças, e inclui proteção contra SSRF e autenticação via header `X-RapidAPI-Proxy-Secret`.

## Módulos

| Módulo | Prefixo | Descrição rápida | Documentação |
| :--- | :--- | :--- | :--- |
| **`sec_audit`** | `/v1` | Auditoria de segurança de URLs (TLS/SSL, headers HTTP de segurança, verificação contra feeds URLhaus e OpenPhish, nota `A+` a `F`). | [app/modules/sec_audit/README.md](app/modules/sec_audit/README.md) |
| **`mail_verify`** | `/v1/email` | Verificação de e-mails (sintaxe estrita RFC/IDNA, registros DNS MX/SPF/DMARC, detecção de domínios descartáveis, sugestão de typo e score de reputação). | [app/modules/mail_verify/README.md](app/modules/mail_verify/README.md) |
| **`doc_extract`** | `/v1/extract` | Extração limpa de conteúdo de páginas web e PDFs em Markdown/texto estruturado, com contagem de tokens via `tiktoken`. | [app/modules/doc_extract/README.md](app/modules/doc_extract/README.md) |

## Autenticação e Healthcheck

- **`GET /health`**: endpoint público (não exige autenticação), retorna `{"status": "ok"}`.
- **Demais rotas (`/v1/...`)**: protegidas pelo `RapidAPIProxyMiddleware`, que exige o header `X-RapidAPI-Proxy-Secret` igual ao valor configurado em `RAPIDAPI_PROXY_SECRET`.

## Configuração e Execução

### 1. Variáveis de ambiente

Copie `.env.example` para `.env` e ajuste os valores:

```bash
cp .env.example .env
```

Principais variáveis:
- `RAPIDAPI_PROXY_SECRET`: segredo esperado no header `X-RapidAPI-Proxy-Secret`.
- `REDIS_URL`: URL de conexão com o Redis (padrão local: `redis://localhost:6379/0`).
- `BASE_DOMAIN` / `ACME_EMAIL`: usados pelo Caddy em produção (`docker-compose.yml`).

### 2. Rodando localmente

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

> Nota: no ambiente Linux, o módulo `doc_extract` pode requerer `tesseract-ocr` e `libmagic1` no sistema (já incluídos no `docker-compose.yml`).

### 3. Rodando com Docker Compose

```bash
docker compose up -d --build
```

Sobe os serviços `api` (FastAPI/Uvicorn na porta interna `8000`), `redis` (`redis:7-alpine`) e `caddy` (`caddy:2-alpine` nas portas `80` e `443`).

## Testes

Use o script `run_tests.py` na raiz do projeto para executar os testes de todos os módulos e exibir uma tabela consolidada:

```bash
.venv/bin/python run_tests.py
```

Opções úteis:
- Rodar módulos específicos: `.venv/bin/python run_tests.py doc_extract mail_verify`
- Detalhar falhas, erros e warnings: `.venv/bin/python run_tests.py -d` (ou `--details`)
- Ver saída completa do `pytest`: `.venv/bin/python run_tests.py -v`

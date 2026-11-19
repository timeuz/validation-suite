# Módulo `sec_audit`

Módulo responsável por realizar auditorias completas de segurança em URLs HTTP/HTTPS, avaliando **TLS/SSL**, **headers HTTP de segurança**, **proteção contra SSRF** em cada redirecionamento e **inteligência de ameaças** (URLhaus e OpenPhish) armazenada no Redis.

- **Prefixo das rotas:** `/v1`
- **Arquivos:** `router.py`, `schemas.py`, `service.py`, `tests.py`

## Endpoints

### `POST /v1/audit`

Executa a auditoria completa de segurança em uma URL alvo.

**Body (`application/json` — `AuditRequest`, `extra="forbid"`, `strict=True`):**

| Campo | Tipo | Padrão | Descrição |
| :--- | :--- | :--- | :--- |
| `url` | `string` | *(obrigatório)* | URL HTTP ou HTTPS alvo (4 a 2048 caracteres). |
| `timeout` | `float` | `10.0` | Timeout de rede em segundos para sondas TLS e HTTP (`1.0` a `30.0`). |
| `follow_redirects` | `boolean` | `true` | Segue redirecionamentos HTTP (cada salto é validado contra SSRF). |
| `sync_feeds` | `boolean` | `false` | Sincroniza os feeds URLhaus e OpenPhish no Redis antes de auditar. |

**Resposta (`AuditResponse`):**
- Identificação e rede: `url`, `final_url`, `hostname`, `resolved_ips`, `http_status`, `audited_at`
- Avaliação geral: `score` (`0` a `100`), `grade` (`"A+"`, `"A"`, `"B"`, `"C"`, `"D"`, `"F"`), `recommendations`
- **`ssl` (`SSLInfo`)**: `enabled`, `valid`, `trusted_chain`, `hostname_match`, `expired`, `not_yet_valid`, `self_signed`, `protocol`, `cipher`, `subject`, `issuer`, `serial_number`, `not_before`, `not_after`, `days_remaining`, `san`, `signature_algorithm`, `key_algorithm`, `key_size`, `errors`, `warnings`
- **`headers` (`HeadersAuditResult`)**: `score` (0–100), `present`, `missing`, `warnings`, `leaked_headers` (ex.: `X-Powered-By`, `Server` verboso), `details` (mapa de `HeaderFinding` com `status`: `"pass" | "warn" | "fail"`, `score_deduction` e `recommendation`)
- **`threat_intel` (`ThreatIntelResult`)**: `is_malicious`, `urlhaus_listed`, `openphish_listed`, `matched_feeds`, `matched_indicators`, `feeds_last_sync`

---

### `POST /v1/audit/feeds/sync`

Sincroniza manualmente os feeds de ameaças **URLhaus** e **OpenPhish** para o Redis (TTL padrão de 3600s). Não exige body.

**Resposta (`FeedSyncResponse`):**
- `synced`: `boolean` indicando se ambos os feeds sincronizaram sem erros
- `urlhaus_count`: quantidade de URLs sincronizadas do URLhaus
- `openphish_count`: quantidade de URLs sincronizadas do OpenPhish
- `synced_at`: timestamp UTC ISO-8601
- `errors`: lista de erros ocorridos durante a sincronização

## Testes

```bash
.venv/bin/python run_tests.py sec_audit
```

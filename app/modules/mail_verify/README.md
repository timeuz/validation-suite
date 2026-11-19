# Módulo `mail_verify`

Módulo responsável por validar endereços de e-mail em múltiplas camadas: sintaxe estrita, registros DNS do domínio, detecção de domínios descartáveis, sugestão de correção de domínio (*did you mean*) e cálculo de score de reputação.

- **Prefixo das rotas:** `/v1/email`
- **Arquivos:** `router.py`, `schemas.py`, `service.py`, `tests.py`

## Endpoints

### `POST /v1/email/verify`

Executa a verificação completa de um endereço de e-mail, utilizando Redis para cache de resultados quando disponível.

**Body (`application/json` — `EmailVerifyRequest`):**

| Campo | Tipo | Descrição |
| :--- | :--- | :--- |
| `email` | `string` | Endereço de e-mail a ser verificado. |

**Validação sintática (`validate_email_syntax_str`):**
- Segue regras estritas baseadas em RFC 5321/5322 e IDNA 2008 / UTS #46 (`email-validator`).
- Máximo de 254 caracteres no total, 1–64 caracteres na parte local e até 253 no domínio.
- Rejeita espaços, caracteres de controle, pontos consecutivos (`..`), pontos no início/fim e TLDs inválidos ou puramente numéricos.

**Resposta (`EmailVerifyResponse`):**

| Campo | Tipo | Descrição |
| :--- | :--- | :--- |
| `email` | `string` | E-mail normalizado. |
| `local_part` | `string` | Parte local (antes do `@`). |
| `domain` | `string` | Domínio do e-mail. |
| `is_valid` | `boolean` | Resultado consolidado da validade do e-mail. |
| `syntax_valid` | `boolean` | Indica se passou na validação sintática. |
| `is_disposable` | `boolean` | Indica se o domínio consta na blocklist de e-mails descartáveis (`disposable-email-domains`). |
| `has_mx` | `boolean` | Indica se o domínio possui registros MX no DNS. |
| `mx_records` | `list[string]` | Lista de servidores MX encontrados. |
| `has_spf` | `boolean` | Indica presença de registro SPF. |
| `spf_record` | `string \| null` | Conteúdo do registro SPF, se encontrado. |
| `has_dmarc` | `boolean` | Indica presença de registro DMARC. |
| `dmarc_record` | `string \| null` | Conteúdo do registro DMARC, se encontrado. |
| `did_you_mean` | `string \| null` | Sugestão de correção caso seja detectado possível erro de digitação no domínio. |
| `reputation_score` | `integer` (0–100) | Pontuação calculada para o domínio. |
| `reputation_status` | `"high" \| "medium" \| "low" \| "blocked" \| "invalid"` | Classificação da reputação. |
| `cached` | `boolean` | Indica se a resposta veio do cache Redis. |

## Testes

```bash
.venv/bin/python run_tests.py mail_verify
```

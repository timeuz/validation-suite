# Módulo `doc_extract`

Módulo responsável por extrair conteúdo limpo de **páginas web públicas** e **documentos PDF**, retornando texto/Markdown estruturado, metadados e contagem de tokens via `tiktoken`.

- **Prefixo das rotas:** `/v1/extract`
- **Arquivos:** `router.py`, `schemas.py`, `service.py`, `tests.py`

## Endpoints

### `POST /v1/extract/url`

Extrai o conteúdo principal de uma URL HTTP(S) pública usando `trafilatura` (com proteção contra SSRF via `app.core.ssrf.validate_url`), opcionalmente utilizando cache no Redis.

**Body (`application/json` — `UrlExtractRequest`):**

| Campo | Tipo | Padrão | Descrição |
| :--- | :--- | :--- | :--- |
| `url` | `string` | *(obrigatório)* | URL HTTP(S) pública (1 a 2048 caracteres, não pode ser vazia). |
| `output_format` | `"markdown" \| "txt"` | `"markdown"` | Formato do conteúdo extraído. |
| `include_links` | `boolean` | `false` | Preserva hiperlinks no texto extraído. |
| `include_tables` | `boolean` | `true` | Inclui tabelas HTML na extração. |
| `include_comments` | `boolean` | `false` | Inclui seções de comentários na extração. |
| `favor_precision` | `boolean` | `false` | Prioriza menor ruído em vez de abrangência. |
| `favor_recall` | `boolean` | `false` | Prioriza maior abrangência quando o conteúdo principal é esparso. |
| `encoding` | `"cl100k_base" \| "o200k_base" \| "p50k_base" \| "r50k_base"` | `"cl100k_base"` | Encoding do `tiktoken` usado na contagem de tokens. |
| `use_cache` | `boolean` | `true` | Consulta o cache Redis antes de buscar a URL. |

**Resposta (`UrlExtractResponse`):**
- `url`, `final_url`, `content`, `output_format`, `char_count`, `token_count`, `encoding`, `cached`
- `metadata` (`WebMetadata`): `title`, `author`, `date`, `sitename`, `language`, `description`

---

### `POST /v1/extract/pdf`

Extrai Markdown estruturado de um PDF enviado via `multipart/form-data` (usando `pymupdf` / `pymupdf4llm`) e calcula a contagem de tokens.

**Limites:** máximo de **10 MB** e **50 páginas** por arquivo.

**Form (`multipart/form-data`):**
- `file`: arquivo PDF (`UploadFile`, obrigatório).
- `encoding`: encoding `tiktoken` (`"cl100k_base"`, `"o200k_base"`, `"p50k_base"` ou `"r50k_base"`; padrão `"cl100k_base"`).

**Resposta (`PdfExtractResponse`):**
- `filename`, `content`, `output_format` (`"markdown"`), `page_count`, `size_bytes`, `char_count`, `token_count`, `encoding`
- `metadata` (`PdfMetadata`): `title`, `author`, `subject`, `creator`, `producer`

## Testes

```bash
.venv/bin/python run_tests.py doc_extract
```

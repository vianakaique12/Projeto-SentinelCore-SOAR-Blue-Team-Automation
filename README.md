# Mini SOAR for SOC (Python)

Projeto de automação de segurança focado em fluxo SOC real:
- Enriquecimento de IOC (VirusTotal + AbuseIPDB)
- Scoring e priorização de risco
- Resposta automática (ticketing e integrações)
- API segura e modo assíncrono com fila
- Observabilidade, persistência e testes

## Por que este projeto é relevante

Este projeto demonstra competências práticas cobradas em vagas de Cybersecurity Junior e Pleno:
- `Python` para automação de segurança
- `Threat Intelligence` e triagem de IOC
- `Detection & Response` com lógica de priorização
- `SOAR/SIEM integration` (TheHive, Splunk, Sentinel)
- `API Security` (API Key/JWT + rate limiting)
- `Reliability` (retry/backoff, idempotência, persistência)
- `Engineering quality` (testes automatizados + CI/CD)

## O que ele faz

1. Recebe IOC(s) por CLI ou API.
2. Detecta o tipo do IOC (`ip`, `domain`, `url`, `hash`).
3. Enriquece com fontes de threat intel.
4. Calcula score de risco e prioridade.
5. Opcionalmente abre ticket e envia para integrações.
6. Anexa mapeamento MITRE ATT&CK + runbook de resposta.
7. Gera relatório JSON e métricas CSV.

## Arquitetura

- `mini_soar.py`: CLI + modo didático interativo
- `mini_soar_core.py`: pipeline principal
- `mini_soar_api.py`: API FastAPI (`/analyze`, `/analyze/async`, `/jobs/{id}`, `/metrics`)
- `mini_soar_queue.py`: fila assíncrona (RQ/Redis)
- `mini_soar_worker.py`: worker de jobs
- `mini_soar_storage.py`: persistência/idempotência (SQLite/Postgres)
- `mini_soar_observability.py`: logs estruturados + métricas Prometheus
- `mini_soar_mitre.py`: mapeamento ATT&CK + runbook
- `tests/`: suíte pytest

## Rodar em 1 comando (Docker)

Subir stack completa (`API + Redis + Worker`):

```powershell
.\start_stack.ps1
```

Parar stack:

```powershell
.\stop_stack.ps1
```

Endpoints:
- API: `http://127.0.0.1:8000`
- Docs: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`
- Metrics: `http://127.0.0.1:8000/metrics`

## Uso rápido (sem Docker)

Instalar dependências:

```powershell
python -m pip install -r .\requirements.txt
```

Executar via CLI:

```powershell
python .\mini_soar.py --input .\iocs.txt --ticket-backend none --output .\report.json
```

Executar API:

```powershell
uvicorn mini_soar_api:app --host 0.0.0.0 --port 8000
```

## Exemplo de chamadas da API

Análise síncrona:

```powershell
curl -X POST http://127.0.0.1:8000/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"ioc\":\"8.8.8.8\",\"ticket_backend\":\"none\"}"
```

Análise assíncrona (fila):

```powershell
curl -X POST http://127.0.0.1:8000/analyze/async ^
  -H "Content-Type: application/json" ^
  -d "{\"iocs\":[\"8.8.8.8\",\"example.com\"],\"integration_targets\":[\"splunk\"]}"
```

Consultar status do job:

```powershell
curl http://127.0.0.1:8000/jobs/SEU_JOB_ID
```

## Segurança e confiabilidade

- API Key/JWT (configurável por env)
- Rate limiting por cliente
- Retry com backoff para conectores externos
- Idempotência para reduzir alert storm
- Persistência de findings (SQLite ou Postgres)
- Logs estruturados e correlação por `correlation_id`
- Métricas Prometheus

## Qualidade de engenharia

- Testes unitários e de API com `pytest`
- Pipeline CI no GitHub Actions (`py_compile + pytest`)

Rodar testes:

```powershell
pytest -q
```

## Variáveis de ambiente

Use `.env.example` como referência para:
- chaves de threat intel
- autenticação de API
- integração com plataformas
- configuração de fila e banco
- parâmetros de confiabilidade

## Como um recrutador pode avaliar em 5 minutos

1. Subir stack com `.\start_stack.ps1`.
2. Abrir `http://127.0.0.1:8000/docs`.
3. Testar `/analyze` com IOC simples.
4. Testar `/analyze/async` e consultar `/jobs/{id}`.
5. Verificar relatório de saída e métricas em `/metrics`.

## Observações

- Projeto para defesa/capacitação em cybersegurança.
- Não versionar chaves reais de API.


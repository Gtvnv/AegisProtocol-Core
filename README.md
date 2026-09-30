# 🛡️ Aegis Protocol - Core Identity Provider

[![Version](https://img.shields.io/badge/version-0.2.0-blue)](https://github.com/Gtvnv/AegisProtocol-Core/releases)
[![Java 21](https://img.shields.io/badge/Powered_by-Java_21-orange)](#)
[![Status](https://img.shields.io/badge/Status-Em_desenvolvimento_ativo-success)](#)

> **Security & IAM Middleware**
> Uma iniciativa [ZenithCode](https://github.com/gtvnv) mantida pela divisão N.Ú.C.L.E.O.

O **Aegis Core** é um Middleware de Segurança e Identity Provider (IdP) projetado com arquitetura **Zero Trust**, evoluindo para um **Network Sentinel** completo. Centraliza autenticação, emissão de tokens criptografados (RSA-2048/RS256), políticas de acesso granulares (ABAC/RBAC), auditoria forense hash-encadeada e conformidade LGPD/ISO 27001 — tudo em desenvolvimento ativo neste repositório.

## 🚀 Tecnologias
- **Java 21** + **Spring Boot 3.4**
- **Spring Security 6** (Stateless Filter Chain)
- **JWT (JJWT)** com Assinatura Assimétrica (RS256)
- **Redis** (Token Blacklist & Revocation)
- **PostgreSQL** (User Store)
- **HashiCorp Vault** (KMS opcional — `aegis.jwt.key-source=vault`; padrão é arquivo local)
- **SMTP** (notificação de incidente ao titular + time de compliance — LGPD Art. 48)
- **Docker** (Containerização)
- **MCP server local** (`mcp-server/`) — base de conhecimento do projeto para sessões de IA assistindo o desenvolvimento

## 🔐 Capacidades por área

### Identidade e Autenticação
- JWT RS256 com rotação de chave zero-downtime (multi-kid) e cofre de chave plugável (arquivo local ou HashiCorp Vault).
- Soft lock: contas novas autenticam mas carregam `verified=false` até confirmação.
- Revogação distribuída via blacklist Redis (logout imediato, rotação de refresh token).
- Rate limiting e detecção de anomalias no registro/login.

### Zero Trust de Rede
- **Network Sentinel**: filtro que roda antes da autenticação em rotas administrativas, validando a origem contra zonas de rede confiáveis (CIDR IPv4 **e IPv6**).
- **S.H.I.E.L.D.**: detecção de lateral movement, fingerprint de sessão e IP-intel, com abertura automática de incidentes em severidade alta.

### Privacidade e Conformidade (LGPD / ISO 27001)
- **PrivacyGate**: pseudonimização HMAC-por-titular do actor antes de qualquer escrita na trilha de auditoria, com crypto-shredding no direito ao esquecimento — inclusive encerramento auditável de cadeias legadas anteriores ao próprio PrivacyGate.
- **Consent Ledger + Consent Gate**: registro versionado de consentimento no cadastro, com bloqueio real de login/renovação de sessão quando o consentimento não está na versão vigente.
- **IAM Self-Service**: exportação de dados (`GET /auth/account/export`) e exclusão de conta com destruição do vínculo de identidade.
- **Retention Engine**: arquivamento (nunca exclusão) de trilhas antigas em lotes com checkpoint assinado e resumível. Purga física, quando legalmente exigida, segue um [runbook manual documentado](docs/retention-purge-runbook.md) — a aplicação nunca apaga sozinha, só registra o recibo de que a purga aconteceu.

### Auditoria e Resposta a Incidentes
- **Cadeia Ômega**: trilha de auditoria hash-encadeada (SHA-256), WORM-hardened, verificável e resistente a adulteração — uma sequência independente por titular.
- **Incident Response Orchestrator**: abertura automática de incidentes por severidade, SLA com varredura de estouro, e notificação real por e-mail ao titular e ao time de compliance.
- **Policy Audit**: CRUD administrado de políticas ABAC/RBAC com snapshot antes/depois auditado.

## 🛠️ Como Rodar

### Pré-requisitos
- Docker & Docker Compose
- Java 21 SDK

### Start Rápido
```bash
# 1. Gerar Chaves RSA (Se não existirem)
# Execute a classe utilitária KeyGen.java ou use OpenSSL

# 2. Build & Run
docker build -t aegis-core:latest .
docker run -p 9090:9090 aegis-core:latest
```

### 📡 Endpoints Principais

**Autenticação**
```
POST   /auth/login                          - Autenticação e emissão de JWT (bloqueia sem consentimento vigente).
POST   /auth/register                       - Registro com proteção anti-spam. Exige consentVersion.
POST   /auth/refresh                        - Renovação de sessão segura (bloqueia sem consentimento vigente).
POST   /auth/logout                         - Revogação imediata do token atual.
GET    /auth/public-key | /auth/public-keys - Chave(s) pública(s) para microsserviços satélites validarem JWTs.
```

**Autoatendimento do titular**
```
GET    /auth/account/export      - Exportação de dados (LGPD Art. 18 / GDPR Art. 15).
DELETE /auth/account             - Exclusão de conta + crypto-shredding do vínculo de identidade.
POST   /auth/consent/withdraw    - Revogação de consentimento.
GET    /auth/consent/current-version - Versão vigente dos termos.
```

**Administração** (`ROLE_ADMIN`)
```
POST   /api/admin/keys/rotate                        - Rotação de chave de assinatura.
GET    /api/admin/audit/chain/history/{actor}         - Timeline de auditoria de um ator.
GET    /api/admin/audit/chain/verify | /verify/{actor} - Verificação de integridade da cadeia.
GET    /api/admin/audit/chain/resolve/{username}       - Tradução username → pseudônimo.
POST   /api/admin/audit/chain/close-legacy-actors      - Encerramento de cadeias legadas em claro.
GET/POST/DELETE /api/admin/network/zones               - CRUD de zonas de rede confiáveis (CIDR IPv4/IPv6).
GET/POST/PUT/DELETE /api/admin/policies                - CRUD de políticas ABAC/RBAC auditado.
POST   /api/admin/retention/run                        - Sweep manual de arquivamento de auditoria.
POST   /api/admin/retention/checkpoints/{id}/mark-purged - Registra purge físico manual já executado (ver docs/retention-purge-runbook.md).
```

## 🔖 Versionamento

Este repositório segue [SemVer](https://semver.org/) em `pom.xml` (`<version>`), sem sufixo `-SNAPSHOT` — não há publicação em artifact repository, então a versão do POM é sempre a versão da release. Cada evolução (satélite) que mergear em `main` recebe:

1. Bump de versão (`MINOR` para satélite novo, `PATCH` para fix/incidental sem satélite novo);
2. Uma tag `vX.Y.Z`;
3. Uma [GitHub Release](https://github.com/Gtvnv/AegisProtocol-Core/releases) com as notas daquela entrega.

**v0.1.0** foi a primeira release sob este esquema. **v0.2.0** fecha o último item do "Roadmap 2" (as lacunas conhecidas identificadas no primeiro round de satélites): o runbook de purga física do Retention Engine — com isso, todas as 13 evoluções mapeadas até aqui (7 satélites originais + 6 itens de follow-up) estão entregues.

---

## 📄 Licença
MIT License - Veja `LICENSE` para detalhes.

---

## 🛡️ Segurança e Resiliência
O AegisProtocol opera sob o modelo Zero Trust, garantindo que nenhum acesso seja confiável por padrão. A camada de segurança conta com um GlobalExceptionHandler especializado para evitar o vazamento de metadados de infraestrutura, além de mecanismos nativos contra Reflected XSS, Log Forging e validação rigorosa de claims na camada de autenticação.

---

*Arquitetado com foco em soberania de dados e proteção de perímetros digitais modernos.* <br/>

<div align="center">
  <b>AegisProtocol</b> é a fundação de segurança e identidade da <b>ZenithCode</b>.<br/>
  Liderado pela divisão <b>N.Ú.C.L.E.O.</b> e arquitetado por <i>Gustavo "Tavera" Ventura</i>.

  <br/><br/>

  [![Arquitetura Limpa](https://img.shields.io/badge/Design-Clean_Architecture-blue)](#)
  [![Java 21](https://img.shields.io/badge/Powered_by-Java_21-orange)](#)
  [![Zero Trust](https://img.shields.io/badge/Architecture-Zero_Trust-critical)](#)

  <br/>

  <sub>Blindando o amanhã, uma conexão por vez. 🚀</sub>
</div>

---

*Desenvolvido com ❤️ em 2026*

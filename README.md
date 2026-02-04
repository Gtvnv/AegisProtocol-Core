# 🛡️ AegisProtocol-Core

![Java](https://img.shields.io/badge/Java-21-LTS?style=for-the-badge&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4+-brightgreen?style=for-the-badge&logo=springboot)
![Security](https://img.shields.io/badge/Security-Zero%20Trust-critical?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**Security Middleware & Identity Service**  
> Zero Trust • Defense in Depth • ABAC/RBAC Hybrid • Secure-by-Default

O **AegisProtocol-Core** é um middleware de segurança avançado desenvolvido em **Java 21** e **Spring Boot 3.4+**, projetado para atuar como a **camada central de proteção** em ecossistemas distribuídos.

Ele implementa princípios modernos de segurança, incluindo:

- **Zero Trust Architecture**
- **Criptografia Assimétrica (RSA)**
- **Autenticação Stateless com JWT**
- **Autorização baseada em políticas (ABAC)**

Ideal para **microserviços**, **APIs críticas**, **plataformas SaaS** e **sistemas distribuídos sensíveis**.

---

## 📚 Table of Contents

- [Tecnologias](#-tecnologias)
- [Arquitetura e Recursos](#-arquitetura-e-recursos)
  - [Autenticação](#-autenticação-zero-trust)
  - [Autorização](#-autorização-híbrida-policy-engine)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Configuração](#️-configuração)
- [Como Executar](#-como-executar)
- [API Endpoints](#-api-endpoints)
- [Roadmap](#-roadmap)
- [Licença](#-licença)

---

## 🚀 Tecnologias

- **Java 21 (LTS)** — Linguagem base
- **Spring Boot 3.4+** — Framework principal
- **Spring Security 6** — Cadeia de filtros de segurança
- **JJWT 0.12.x** — Criação e validação de JWT
- **RSA 2048-bit** — Assinatura criptográfica de tokens
- **Lombok** — Redução de boilerplate
- **Maven** — Gerenciamento de dependências

---

## 🧠 Arquitetura e Recursos

### 🔐 Autenticação (Zero Trust)

- **JWT Assinado com RSA**
  - Aegis assina tokens com chave **privada**
  - Microsserviços validam com chave **pública**
  - Elimina compartilhamento de segredo (HMAC)

- **Token Rotation**
  - Access Token: **curta duração (5 min)**
  - Refresh Token: **longa duração**

- **Stateless**
  - Sem sessão no servidor
  - `SessionCreationPolicy.STATELESS`

---

### 🧩 Autorização Híbrida (Policy Engine)

O Aegis implementa um **Policy Decision Engine** que vai além do RBAC tradicional.

#### Modelo ABAC

Baseado em quatro pilares:

- **Subject** — Quem está acessando
- **Resource** — O que está sendo acessado
- **Action** — Qual ação está sendo executada
- **Environment** — Contexto da requisição

#### Recursos

- Regras dinâmicas e compostas
- Operadores lógicos:
  - `EQUALS`
  - `GREATER_THAN`
  - `CONTAINS`
  - `MATCHES`
- **Secure-by-Default**
  - Nenhuma política encontrada → **DENY**

---

## 🧱 Estrutura do Projeto

Organização focada em **domínios de segurança**, inspirada em Clean Architecture:

```plaintext
br.com.github.gtvnv
├── authentication      # Login, KeyProvider, TokenService, JwtFilter
├── authorization       # Interfaces de decisão de acesso
├── config              # SecurityConfig, JwtProperties
├── domain              # Modelos e regras da Policy Engine
│   ├── model           # AccessContext, Subject, Resource, Environment
│   └── policy          # Policy, Condition, Target, Effect
├── engine              # PolicyEvaluator (core do ABAC)
├── audit               # (Planejado) Audit Trail imutável
└── threat              # (Planejado) Detecção de ameaças
```

--- 

### ⚙️ Configuração

Exemplo de configuração no application.properties:

# Configurações JWT - Aegis Protocol
- aegis.jwt.access-token-expiration=300     # 5 minutos
- aegis.jwt.refresh-token-expiration=86400  # 24 horas

---

### ⚡ Como Executar
- Pré-requisitos

- JDK 21+

- Maven 3.9+

### Passos

Clone o repositório:

```
git clone https://github.com/gtvnv/aegisprotocol-core.git
cd aegisprotocol-core
```

Compile o projeto:
```
mvn clean install
```

Execute a aplicação:

```
mvn spring-boot:run
```

### 🔌 API Endpoints
### 🔐 Autenticação

POST /auth/login
```
{
  "username": "admin",
  "password": "123456"
}
```

Response:
```
{
  "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 300
}
```
### 🔒 Recurso Protegido

```
- GET /api/secret

- Authorization: Bearer <access_token>

- ACESSO PERMITIDO! O sistema Aegis está ativo.
```
---
### 🗺️ Roadmap

 - Arquitetura base

 - JWT com RSA

 - Policy Engine ABAC

 - Spring Security Filter Chain

### Próximos Passos

 - Redis (Refresh Token + Blacklist)

 - Integração ABAC com AuthorizationManager

 - Audit Trail imutável

 - Rate Limiting

 - Análise de reputação de IP

 - Threat Detection

---

<div align="center"> <sub>AegisProtocol-Core © 2026
Desenvolvido com foco em excelência arquitetural, segurança real e engenharia de alto nível.
</div>
# 🛡️ Aegis Protocol - Core Identity Provider (v1.0.0)

> **Security & IAM Middleware**
> Uma iniciativa [ZenithCode](https://github.com/gtvnv) mantida pela divisão N.Ú.C.L.E.O.

O **Aegis Core** é um Middleware de Segurança e Identity Provider (IdP) projetado com arquitetura **Zero Trust**. Ele centraliza a autenticação, emissão de tokens criptografados (RSA-2048) e políticas de acesso granulares (ABAC/RBAC).

## 🚀 Tecnologias
- **Java 21** + **Spring Boot 3.4**
- **Spring Security 6** (Stateless Filter Chain)
- **JWT (JJWT)** com Assinatura Assimétrica (RS256)
- **Redis** (Token Blacklist & Revocation)
- **PostgreSQL** (User Store)
- **Docker** (Containerização)

## 🔐 Key Features
1.  **Zero Trust Architecture:** Nenhuma requisição é confiável por padrão.
2.  **Soft Lock Mechanism:** Usuários podem logar, mas recursos sensíveis exigem verificação (Claim-based security).
3.  **Threat Mitigation:** Rate Limiting e detecção de anomalias no registro.
4.  **Token Revocation:** Blacklist distribuída via Redis para logout imediato.
5.  **Key Rotation Ready:** Arquitetura preparada para rotação de chaves sem downtime.

## 🛠️ Como Rodar

### Pré-requisitos
- Docker & Docker Compose
- Java 21 SDK

### Start Rápido
```bash
# 1. Gerar Chaves RSA (Se não existirem)
# Execute a classe utilitária KeyGen.java ou use OpenSSL

# 2. Build & Run
docker build -t aegis-core:v1 .
docker run -p 9090:9090 aegis-core:v1
```

### 📡 Endpoints Principais
```
POST /auth/login - Autenticação e emissão de JWT.

POST /auth/register - Registro com proteção anti-spam.

POST /auth/refresh - Renovação de sessão segura.

GET /auth/public-key - Exposição da JWK (Public Key) para microsserviços satélites.
```

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
  [![Status](https://img.shields.io/badge/Status-Alpha_v1-success)](#)

  <br/>

  <sub>Blindando o amanhã, uma conexão por vez. 🚀</sub>
</div>

---

*Desenvolvido com ❤️ em 2026*

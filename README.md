# 🛡️ Aegis Protocol - Core Identity Provider (v1.0.0)

> "Identity is the new perimeter."

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

## 👨‍💻 Autor
**Gustavo Ventura** - [GitHub](https://github.com/Gtvnv)

---

*Desenvolvido com ❤️ em 2026*
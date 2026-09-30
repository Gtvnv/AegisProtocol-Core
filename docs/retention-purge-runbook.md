# Runbook: Purga Física de Auditoria Arquivada

Módulo Ômega / Retention Engine — operação **manual**, executada por um
DBA/superuser fora da aplicação. O Retention Engine (ver
`RetentionProperties`) **nunca apaga nada sozinho**: ele arquiva lotes de
`audit_chain_entries` fora da janela de retenção em NDJSON + um
`RetentionCheckpoint` assinado, e é só isso. A cadeia é WORM-hardened
(`docs/worm-hardening.sql`) — o usuário da aplicação nem tem permissão de
`DELETE` na tabela.

Este runbook existe pra quando (e só quando) a purga física for **legalmente
exigida** — a maioria dos ambientes nunca precisa executá-lo, já que arquivar
sozinho normalmente já satisfaz o requisito de minimização de dados enquanto
a trilha continua auditável. Não execute isto por rotina.

## Pré-condições

- Confirme que existe uma exigência legal/contratual concreta para a purga
  física (não é uma limpeza de espaço em disco — para isso, mova o arquivo
  NDJSON para armazenamento mais barato, não o delete).
- Confirme que o checkpoint em questão está **fora de qualquer legal hold**
  ativo (litígio, investigação em andamento, etc. — fora do escopo deste
  repositório saber disso automaticamente).
- Acesso de superuser/DBA ao PostgreSQL (o usuário da aplicação,
  `aegis_app_user`, não tem `DELETE` em `audit_chain_entries` — de propósito,
  ver `docs/worm-hardening.sql`).
- `ROLE_ADMIN` na API, para o passo final de registro.

## Passo a passo

### 1. Identifique o checkpoint

```
GET /api/admin/retention/checkpoints
```

Cada `RetentionCheckpoint` é o recibo de um lote já arquivado: `actor`,
`fromSequence`/`toSequence` (a faixa exata de `audit_chain_entries` coberta),
`archiveFile`, `archiveChecksum`, `entryCount`.

### 2. Verifique a integridade do arquivo ANTES de apagar qualquer coisa

```
GET /api/admin/retention/checkpoints/{id}/verify
```

Recalcula o checksum do NDJSON arquivado e compara com o gravado no
checkpoint. Se `intact: false`, **pare** — o arquivo foi alterado ou está
ausente/corrompido desde o arquivamento, e apagar as linhas de origem sem um
arquivo íntegro destrói a única cópia que resta daquele lote. Investigue
antes de continuar.

### 3. (Recomendado) Backup adicional fora do banco

Copie `archiveFile` para armazenamento externo (cold storage / WORM bucket)
antes de apagar qualquer coisa do Postgres — o NDJSON arquivado passa a ser a
**única** cópia remanescente daquelas entries depois do passo 4.

### 4. Apague as linhas cobertas pelo checkpoint (como superuser)

```sql
-- Rode como superuser — aegis_app_user não tem permissão de DELETE aqui.
DELETE FROM audit_chain_entries
WHERE actor = '<checkpoint.actor>'
  AND "sequenceNumber" BETWEEN <checkpoint.fromSequence> AND <checkpoint.toSequence>;
```

Use exatamente `actor`, `fromSequence` e `toSequence` do checkpoint — não um
intervalo de tempo aproximado. A cadeia é encadeada por `previousHash` dentro
da sequência de cada ator; apagar fora da faixa exata de um checkpoint já
verificado quebra a prova de integridade do que restar.

### 5. Apague o arquivo NDJSON local (se não for mais precisar dele)

Só depois de confirmar o backup externo do passo 3, se aplicável.

### 6. Registre o purge — fecha o rastro auditável

```
POST /api/admin/retention/checkpoints/{id}/mark-purged
```

Isto **não apaga nada** — grava `purgedAt`/`purgedBy` no checkpoint e publica
`RETENTION_PHYSICAL_PURGE_RECORDED` no Ômega (assinado, sob o ator
administrador que executou a chamada). É o recibo de que o passo 4 aconteceu,
por quem e quando — sem isso, não haveria nenhum jeito de provar depois que a
purga foi uma decisão auditada e não um apagamento silencioso.

Chamar este endpoint duas vezes para o mesmo checkpoint falha com
`IllegalStateException` (400) de propósito — é quase sempre um erro de
operador (clique duplo, purge já registrado antes). Se isso acontecer e você
tem certeza que é a mesma purga, não é preciso registrar de novo: o registro
já existe.

## Por que isto é manual e não um botão “purgar” na API

O mesmo motivo do WORM hardening em si: uma purga física é irreversível e,
diferente de arquivar, remove completamente a evidência da cadeia. Automatizar
esse gatilho tornaria trivial (um bug, uma chamada de API mal-configurada,
um token comprometido) destruir prova de auditoria sem revisão humana. O
runbook garante que sempre exista um DBA decidindo, deliberadamente, com o
checksum já verificado na mão.

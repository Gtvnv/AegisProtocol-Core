-- =============================================================================
-- WORM Hardening — audit_chain_entries
-- Módulo Ômega / Framework Themis
--
-- Executar como superuser APÓS o primeiro startup da aplicação
-- (o Hibernate cria a tabela via ddl-auto: update no primeiro boot).
--
-- OBJETIVO: Impedir que o usuário da aplicação (aegis_app_user) altere ou
-- delete qualquer entry da cadeia criptográfica. INSERT e SELECT permanecem.
-- Adulterações só seriam possíveis como superuser — detectável via log do DBA.
-- =============================================================================

-- 1. Revogar UPDATE e DELETE do usuário da aplicação
REVOKE UPDATE, DELETE ON TABLE audit_chain_entries FROM aegis_app_user;

-- 2. Garantir que INSERT e SELECT continuam permitidos
GRANT INSERT, SELECT ON TABLE audit_chain_entries TO aegis_app_user;

-- 3. Constraint de unicidade no selfHash (garante imutabilidade estrutural)
--    Já criada pelo Hibernate via @Column(unique=true), mas explicitamos aqui
--    para documentação e para recriar em caso de migration manual.
-- ALTER TABLE audit_chain_entries
--     ADD CONSTRAINT uq_audit_chain_self_hash UNIQUE (self_hash);

-- 4. (Opcional) Trigger que bloqueia qualquer UPDATE mesmo por superuser
--    Usar apenas em ambientes com requisito de auditoria máxima.
-- CREATE OR REPLACE FUNCTION prevent_audit_chain_update()
-- RETURNS TRIGGER AS $$
-- BEGIN
--     RAISE EXCEPTION 'audit_chain_entries é imutável. Adulteração detectada.';
-- END;
-- $$ LANGUAGE plpgsql;
--
-- CREATE TRIGGER trg_prevent_audit_chain_update
-- BEFORE UPDATE OR DELETE ON audit_chain_entries
-- FOR EACH ROW EXECUTE FUNCTION prevent_audit_chain_update();

-- =============================================================================
-- Verificação pós-execução:
--   SELECT grantee, privilege_type
--   FROM information_schema.role_table_grants
--   WHERE table_name = 'audit_chain_entries';
--
-- Resultado esperado: aegis_app_user tem apenas INSERT e SELECT.
-- =============================================================================

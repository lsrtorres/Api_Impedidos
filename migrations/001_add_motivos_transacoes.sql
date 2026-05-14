-- ============================================================
-- Migration 001 - Adiciona coluna motivos na tabela transacoes
-- Banco: Api_Impedidos
-- Data: 2026-04-14
-- Motivo: A API SERPRO passou a retornar motivos como lista
--         (ex: ["PROGRAMA_SOCIAL", "AUTOEXCLUSAO_CENTRALIZADA"])
--         ao invés de um único campo string.
-- Executar uma única vez. Coluna nullable para não quebrar
-- registros históricos existentes.
-- ============================================================

ALTER TABLE transacoes
ADD motivos NVARCHAR(MAX) NULL;
GO

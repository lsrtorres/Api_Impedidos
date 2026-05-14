-- ============================================================
-- Migration 002 - Adiciona coluna data_autoexclusao na tabela transacoes
-- Banco: Api_Impedidos
-- Data: 2026-04-14
-- Motivo: Armazenar dataSolicitacaoAutoexclusao retornada pelo SERPRO
--         para que o atendimento saiba desde quando o usuario está autoexcluído.
-- Coluna nullable — só é preenchida quando o motivo inclui AUTOEXCLUSAO_CENTRALIZADA.
-- ============================================================

ALTER TABLE transacoes
ADD data_autoexclusao NVARCHAR(50) NULL;
GO

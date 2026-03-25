-- ============================================================================
-- IRIS-VE v4.0 → v4.1 Migration Script
-- Aggiunge supporto storage S3/MinIO al database esistente
-- ============================================================================
-- NOTA: Eseguire DOPO un backup del database!
--   mysqldump -u root -p iris_ve > backup_pre_migration.sql
-- ============================================================================

USE iris_ve;

-- 1. Aggiungi colonne S3 a storage_config (se non esistono)
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'storage_config'
      AND COLUMN_NAME = 'storage_backend'
);
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE storage_config
        ADD COLUMN storage_backend VARCHAR(20) NOT NULL DEFAULT ''local'' AFTER active_disk_path,
        ADD COLUMN s3_bucket VARCHAR(255) NULL DEFAULT NULL AFTER storage_backend,
        ADD COLUMN s3_endpoint VARCHAR(512) NULL DEFAULT NULL AFTER s3_bucket',
    'SELECT ''Colonne S3 già presenti in storage_config'' AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2. Aggiungi indice su files.uploaded_by_id (se non esiste)
SET @idx_exists = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'files'
      AND INDEX_NAME = 'ix_files_uploaded_by_id'
);
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE files ADD INDEX ix_files_uploaded_by_id (uploaded_by_id)',
    'SELECT ''Indice ix_files_uploaded_by_id già presente'' AS info'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 3. Verifica
SELECT
    'Migrazione v4.0 → v4.1 completata!' AS status,
    NOW() AS timestamp;

SELECT COLUMN_NAME, COLUMN_TYPE, COLUMN_DEFAULT
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'storage_config'
ORDER BY ORDINAL_POSITION;

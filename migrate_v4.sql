-- ============================================================================
-- IRIS-VE v4.0 — Migration Script
-- Aggiunge: sottocartelle (parent_id), ordinamento drag&drop (folder_orders)
-- Da eseguire su un database IRIS-VE esistente >= v3.0
-- Idempotente: sicuro da rieseguire più volte
-- ============================================================================

USE iris_ve;

-- ============================================================================
-- 1. Aggiungere parent_id alla tabella folders (sottocartelle)
-- ============================================================================

SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'folders'
      AND COLUMN_NAME  = 'parent_id'
);

SET @sql = IF(@col_exists = 0,
    'ALTER TABLE folders ADD COLUMN parent_id INT NULL DEFAULT NULL AFTER workspace_id',
    'SELECT "parent_id already exists" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- FK auto-referenziante (cartella padre → figli in cascade)
SET @fk_exists = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'folders'
      AND CONSTRAINT_NAME = 'fk_folder_parent'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY'
);
SET @sql = IF(@fk_exists = 0,
    'ALTER TABLE folders ADD CONSTRAINT fk_folder_parent FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE',
    'SELECT "fk_folder_parent already exists" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Indice su parent_id
SET @idx_exists = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'folders'
      AND INDEX_NAME   = 'ix_folders_parent_id'
);
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE folders ADD INDEX ix_folders_parent_id (parent_id)',
    'SELECT "ix_folders_parent_id already exists" AS info'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ============================================================================
-- 2. Nuova tabella folder_orders (ordine drag&drop per utente)
-- ============================================================================

CREATE TABLE IF NOT EXISTS folder_orders (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    workspace_id   INT NULL DEFAULT NULL,  -- NULL = spazio personale
    folder_id      INT NOT NULL,
    position       INT NOT NULL DEFAULT 0,

    UNIQUE KEY uq_user_ws_folder (user_id, workspace_id, folder_id),
    INDEX ix_fo_user_ws (user_id, workspace_id),
    INDEX ix_fo_folder  (folder_id),

    CONSTRAINT fk_fo_user   FOREIGN KEY (user_id)      REFERENCES users(id)      ON DELETE CASCADE,
    CONSTRAINT fk_fo_ws     FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    CONSTRAINT fk_fo_folder FOREIGN KEY (folder_id)    REFERENCES folders(id)    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 3. Aggiornare view v_workspace_stats per includere sottocartelle
-- ============================================================================

CREATE OR REPLACE VIEW v_workspace_stats AS
SELECT
    w.id   AS workspace_id,
    o.name AS org_name,
    COUNT(DISTINCT f.id)  AS total_folders,
    COUNT(DISTINCT fi.id) AS total_files,
    COALESCE(SUM(fi.size), 0) AS total_size_bytes,
    MAX(f.created_at) AS last_folder_created
FROM workspaces w
JOIN organizations o ON w.organization_id = o.id
LEFT JOIN folders f  ON f.workspace_id = w.id          -- include sottocartelle (parent_id != NULL)
LEFT JOIN files fi   ON fi.folder_id = f.id
GROUP BY w.id, o.name;

-- ============================================================================
-- VERIFICA
-- ============================================================================

SELECT
    'Migration v4.0 completata' AS status,
    NOW()                       AS applied_at,
    (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='folders' AND COLUMN_NAME='parent_id') AS parent_id_added,
    (SELECT COUNT(*) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='folder_orders') AS folder_orders_created;


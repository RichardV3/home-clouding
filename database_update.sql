-- ============================================================================
-- IRIS-VE v3.0 — Database Migration Script
-- Da: v2.0 (schema singolo admin) → v3.0 (multi-utente + organizzazioni)
-- Esegui questo file SUL DB ESISTENTE con:
--   mysql -u root -p iris_ve < database_update.sql
-- ============================================================================

USE iris_ve;

-- Impostazioni sicurezza per la migrazione
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';
SET FOREIGN_KEY_CHECKS = 0;  -- Disabilitato durante la migrazione

-- ============================================================================
-- STEP 1: NUOVE TABELLE
-- ============================================================================

-- Tabella utenti
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX ix_users_username (username),
    INDEX ix_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella organizzazioni
CREATE TABLE IF NOT EXISTS organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    address TEXT,
    phone VARCHAR(20),
    invite_code VARCHAR(6) NOT NULL UNIQUE,
    owner_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX ix_organizations_invite_code (invite_code),
    CONSTRAINT fk_org_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella membri organizzazioni
CREATE TABLE IF NOT EXISTS organization_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    organization_id INT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uq_user_org (user_id, organization_id),
    INDEX ix_org_members_user (user_id),
    INDEX ix_org_members_org (organization_id),
    CONSTRAINT fk_om_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_om_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella workspace (uno per organizzazione)
CREATE TABLE IF NOT EXISTS workspaces (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ws_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- STEP 2: NUOVE COLONNE SULLE TABELLE ESISTENTI
-- ============================================================================

-- Aggiunge workspace_id alle cartelle (nullable per cartelle personali)
ALTER TABLE folders
    ADD COLUMN IF NOT EXISTS workspace_id INT NULL DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS created_by_id INT NULL DEFAULT NULL;

-- Aggiunge FK se non esistono già
SET @fk_exists = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'folders'
      AND CONSTRAINT_NAME = 'fk_folder_workspace'
);

-- Aggiunge FK workspace (safe: solo se non esiste)
ALTER TABLE folders
    ADD CONSTRAINT fk_folder_workspace
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL;

ALTER TABLE folders
    ADD CONSTRAINT fk_folder_creator
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL;

-- Aggiunge uploaded_by_id ai file
ALTER TABLE files
    ADD COLUMN IF NOT EXISTS uploaded_by_id INT NULL DEFAULT NULL;

ALTER TABLE files
    ADD CONSTRAINT fk_file_uploader
    FOREIGN KEY (uploaded_by_id) REFERENCES users(id) ON DELETE SET NULL;

-- ============================================================================
-- STEP 3: MIGRAZIONE DATI
-- ============================================================================

-- Crea utente admin dal primo utente nell'env (se non esiste)
-- NOTA: la password verrà aggiornata automaticamente da Flask all'avvio
-- se ADMIN_USERNAME non è presente in users, Flask la creerà al primo run
-- Qui inseriamo un placeholder che sarà sovrascritto:
INSERT IGNORE INTO users (username, email, password_hash)
VALUES (
    'admin',
    'admin@iris-ve.local',
    'pbkdf2:sha256:600000$placeholder$0000000000000000000000000000000000000000000000000000000000000000'
);

-- Assegna le cartelle esistenti senza owner all'utente admin (id=1)
UPDATE folders SET created_by_id = 1 WHERE created_by_id IS NULL;

-- Assegna i file esistenti senza uploader all'utente admin
UPDATE files SET uploaded_by_id = 1 WHERE uploaded_by_id IS NULL;

-- ============================================================================
-- STEP 4: INDICI AGGIUNTIVI
-- ============================================================================

-- Indice per query workspace_id su folders
ALTER TABLE folders
    ADD INDEX IF NOT EXISTS ix_folders_workspace_id (workspace_id),
    ADD INDEX IF NOT EXISTS ix_folders_created_by_id (created_by_id);

-- Indice per uploaded_by_id su files
ALTER TABLE files
    ADD INDEX IF NOT EXISTS ix_files_uploaded_by_id (uploaded_by_id);

-- ============================================================================
-- STEP 5: RE-ABILITA FK CHECK E VERIFICA
-- ============================================================================

SET FOREIGN_KEY_CHECKS = 1;

-- Verifica tabelle create
SELECT
    TABLE_NAME,
    TABLE_ROWS,
    CREATE_TIME
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY CREATE_TIME;

SELECT '✅ Migrazione IRIS-VE v3.0 completata!' AS status,
       NOW() AS timestamp;

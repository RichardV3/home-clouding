-- ============================================================================
-- IRIS-VE v4.0 Database Setup Script
-- Multi-user Cloud Storage with Organizations, Workspaces, Custom Roles,
-- Multi-disk, Sottocartelle e Ordinamento Drag&Drop per utente
-- Versione: 4.0.0 — Data: 2026-03-24
-- ============================================================================

-- Creazione database (se non esiste)
CREATE DATABASE IF NOT EXISTS iris_ve
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE iris_ve;

-- Impostazioni ottimizzazione
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';
SET time_zone = '+00:00';

-- ============================================================================
-- TABELLE UTENTI E ACCESSO
-- ============================================================================

-- Tabella utenti (registrazione multi-utente)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    -- v3.2: dati personali opzionali
    first_name VARCHAR(100) NULL DEFAULT NULL,
    last_name VARCHAR(100) NULL DEFAULT NULL,
    phone VARCHAR(20) NULL DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX ix_users_username (username),
    INDEX ix_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABELLE ORGANIZZAZIONI E WORKSPACE
-- ============================================================================

-- Tabella organizzazioni/aziende
CREATE TABLE IF NOT EXISTS organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    address TEXT,
    phone VARCHAR(20),
    invite_code VARCHAR(6) NOT NULL UNIQUE,
    owner_id INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX ix_organizations_invite_code (invite_code),
    INDEX ix_organizations_owner (owner_id),
    CONSTRAINT fk_org_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella membri organizzazione (relazione user ↔ organization)
CREATE TABLE IF NOT EXISTS organization_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    organization_id INT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'member',  -- 'owner' | 'member'
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- v3.1: ruolo personalizzato e permessi manuali
    custom_role_id INT NULL DEFAULT NULL,
    permissions_override JSON NULL DEFAULT NULL,

    UNIQUE KEY uq_user_org (user_id, organization_id),
    INDEX ix_org_members_user (user_id),
    INDEX ix_org_members_org (organization_id),
    CONSTRAINT fk_om_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_om_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
    -- fk_members_role aggiunto dopo org_roles (vedi sotto)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABELLE RUOLI PERSONALIZZATI (v3.1)
-- ============================================================================

-- Ruoli personalizzati per organizzazione con permessi granulari
CREATE TABLE IF NOT EXISTS org_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions JSON NOT NULL,
    color VARCHAR(20) NOT NULL DEFAULT 'accent',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uq_org_role_name (organization_id, name),
    INDEX ix_org_roles_org (organization_id),
    CONSTRAINT fk_org_roles_org FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Aggiunge FK custom_role_id ora che org_roles esiste
ALTER TABLE organization_members
    ADD CONSTRAINT fk_members_role
    FOREIGN KEY (custom_role_id) REFERENCES org_roles(id) ON DELETE SET NULL;

-- Tabella workspace (uno per organizzazione — auto-creato alla creazione org)
CREATE TABLE IF NOT EXISTS workspaces (
    id INT AUTO_INCREMENT PRIMARY KEY,
    organization_id INT NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ws_org FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- CONFIGURAZIONE STORAGE MULTI-DISCO (v3.1)
-- ============================================================================

-- Configurazione disco attivo (riga singola — aggiornata al cambio disco)
CREATE TABLE IF NOT EXISTS storage_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    active_disk_path VARCHAR(512) NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABELLE STORAGE (CARTELLE E FILE)
-- ============================================================================

-- Cartelle normali e cifrate (con supporto sottocartelle via parent_id)
CREATE TABLE IF NOT EXISTS folders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    icon VARCHAR(64) DEFAULT 'bi-folder-fill',
    is_encrypted BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255),
    salt VARCHAR(255),
    workspace_id INT NULL DEFAULT NULL,       -- NULL = cartella personale
    parent_id    INT NULL DEFAULT NULL,       -- NULL = cartella root; altrimenti = sottocartella
    created_by_id INT NULL DEFAULT NULL,      -- NULL = legacy (prima della v3.0)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX ix_folders_name (name),
    INDEX ix_folders_workspace_id (workspace_id),
    INDEX ix_folders_parent_id (parent_id),
    INDEX ix_folders_created_by_id (created_by_id),
    INDEX ix_folders_created_at (created_at DESC),

    CONSTRAINT fk_folder_workspace FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE SET NULL,
    CONSTRAINT fk_folder_creator   FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_folder_parent    FOREIGN KEY (parent_id)     REFERENCES folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- File caricati
CREATE TABLE IF NOT EXISTS files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    folder_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    original_name VARCHAR(255),
    size BIGINT NOT NULL,
    mime_type VARCHAR(100),
    file_path VARCHAR(512) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_encrypted BOOLEAN DEFAULT FALSE,
    uploaded_by_id INT NULL DEFAULT NULL,

    INDEX ix_files_folder_id (folder_id),
    INDEX ix_files_name (name),
    INDEX ix_files_uploaded_at (created_at DESC),
    INDEX ix_files_size (size DESC),
    INDEX ix_files_uploaded_by_id (uploaded_by_id),

    CONSTRAINT fk_file_folder FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_file_uploader FOREIGN KEY (uploaded_by_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Ordine drag&drop cartelle per utente (v4.0)
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
-- AUDIT E ANALYTICS
-- ============================================================================

-- Audit log sicurezza e attività
CREATE TABLE IF NOT EXISTS action_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    folder_id INT NULL,
    file_id INT NULL,
    details TEXT,
    ip_address VARCHAR(50),
    user_agent VARCHAR(255),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX ix_action_logs_timestamp (timestamp DESC),
    INDEX ix_action_logs_folder_id (folder_id),
    INDEX ix_action_logs_action (action),

    CONSTRAINT fk_log_folder FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
    CONSTRAINT fk_log_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- VIEWS PER ANALYTICS
-- ============================================================================

-- Vista statistiche cartelle per workspace
CREATE OR REPLACE VIEW v_workspace_stats AS
SELECT
    w.id AS workspace_id,
    o.name AS org_name,
    COUNT(DISTINCT f.id) AS total_folders,
    COUNT(DISTINCT fi.id) AS total_files,
    COALESCE(SUM(fi.size), 0) AS total_size_bytes,
    MAX(f.created_at) AS last_folder_created
FROM workspaces w
JOIN organizations o ON w.organization_id = o.id
LEFT JOIN folders f ON f.workspace_id = w.id
LEFT JOIN files fi ON fi.folder_id = f.id
GROUP BY w.id, o.name;

-- Vista statistiche utente
CREATE OR REPLACE VIEW v_user_stats AS
SELECT
    u.id AS user_id,
    u.username,
    COUNT(DISTINCT f.id) AS personal_folders,
    COUNT(DISTINCT fi.id) AS total_files,
    COALESCE(SUM(fi.size), 0) AS total_size_bytes,
    COUNT(DISTINCT om.organization_id) AS org_count
FROM users u
LEFT JOIN folders f ON f.created_by_id = u.id AND f.workspace_id IS NULL
LEFT JOIN files fi ON fi.uploaded_by_id = u.id
LEFT JOIN organization_members om ON om.user_id = u.id
GROUP BY u.id, u.username;

-- Vista audit summary (ultimi 30 giorni)
CREATE OR REPLACE VIEW v_daily_audit_summary AS
SELECT
    DATE(timestamp) AS audit_date,
    COUNT(*) AS total_actions,
    COUNT(DISTINCT ip_address) AS unique_ips,
    action,
    COUNT(*) AS action_count
FROM action_logs
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(timestamp), action
ORDER BY audit_date DESC, action_count DESC;

-- ============================================================================
-- STORED PROCEDURES
-- ============================================================================

DROP PROCEDURE IF EXISTS CleanupOldData;
DELIMITER //
CREATE PROCEDURE CleanupOldData()
BEGIN
    DELETE FROM action_logs WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY);
    DELETE FROM query_cache WHERE expires_at < NOW();
    ANALYZE TABLE folders, files, action_logs, users, organizations;
    SELECT 'Cleanup completato' AS status;
END //
DELIMITER ;

DROP PROCEDURE IF EXISTS GetSystemOverview;
DELIMITER //
CREATE PROCEDURE GetSystemOverview()
BEGIN
    SELECT
        (SELECT COUNT(*) FROM users) AS total_users,
        (SELECT COUNT(*) FROM organizations) AS total_orgs,
        (SELECT COUNT(*) FROM workspaces) AS total_workspaces,
        (SELECT COUNT(*) FROM folders) AS total_folders,
        (SELECT COUNT(*) FROM files) AS total_files,
        (SELECT COALESCE(SUM(size), 0) FROM files) AS total_size_bytes,
        NOW() AS generated_at;
END //
DELIMITER ;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

DROP TRIGGER IF EXISTS audit_file_deletion;
DELIMITER //
CREATE TRIGGER audit_file_deletion
AFTER DELETE ON files
FOR EACH ROW
BEGIN
    INSERT INTO action_logs (action, resource_type, details, ip_address)
    VALUES ('file_deleted', 'file',
            CONCAT('File: ', OLD.name, ', Size: ', OLD.size),
            'system');
END //
DELIMITER ;

-- ============================================================================
-- TABELLA CACHE (opzionale — usata da Flask-Caching se configurato con DB)
-- ============================================================================

CREATE TABLE IF NOT EXISTS query_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cache_key VARCHAR(255) NOT NULL UNIQUE,
    cached_data LONGTEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    hit_count INT DEFAULT 0,

    INDEX idx_cache_key (cache_key),
    INDEX idx_cache_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- OTTIMIZZAZIONI DATABASE
-- ============================================================================

SET GLOBAL innodb_buffer_pool_size = 134217728;   -- 128 MB
SET GLOBAL max_connections = 100;
SET GLOBAL innodb_flush_log_at_trx_commit = 2;    -- Performance boost
SET GLOBAL event_scheduler = ON;

-- Cleanup automatico giornaliero
CREATE EVENT IF NOT EXISTS daily_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS (DATE(NOW()) + INTERVAL 1 DAY + INTERVAL 2 HOUR)
DO CALL CleanupOldData();

-- ============================================================================
-- VERIFICA INSTALLAZIONE
-- ============================================================================

SELECT
    TABLE_NAME,
    TABLE_ROWS,
    ENGINE
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_NAME;

SELECT
    'Database IRIS-VE v4.0 configurato con successo!' AS message,
    NOW() AS timestamp,
    DATABASE() AS current_database,
    @@version AS mysql_version;

SELECT '✅ Installazione IRIS-VE v4.0 completata!' AS final_status;

-- IRIS-VE v2.0 Database Setup Script
-- Apple-Inspired Cloud Storage System
-- Versione: 2.0.0
-- Data: 22 Settembre 2025

-- Creazione database (se non esiste)
CREATE DATABASE IF NOT EXISTS python 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE python;

-- Impostazioni ottimizzazione
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO';
SET time_zone = '+00:00';

-- =======================
-- TABELLE PRINCIPALI
-- =======================

-- Tabella cartelle normali (migliorata)
CREATE TABLE IF NOT EXISTS folder (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    created_by VARCHAR(100) NOT NULL DEFAULT 'irisve-cloud',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    is_public BOOLEAN DEFAULT FALSE,
    access_count INT DEFAULT 0,
    last_accessed DATETIME NULL,
    color VARCHAR(7) DEFAULT '#007AFF',
    icon VARCHAR(64) DEFAULT 'bi-folder-fill',

    -- Indici per performance
    INDEX idx_folder_name (name),
    INDEX idx_folder_created_at (created_at DESC),
    INDEX idx_folder_access_count (access_count DESC),
    INDEX idx_folder_public (is_public)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella cartelle crittografate (migliorata)
CREATE TABLE IF NOT EXISTS encrypted_folders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    encrypted_content TEXT NOT NULL,
    salt VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    access_count INT DEFAULT 0,
    last_accessed DATETIME NULL,
    password_hint VARCHAR(255),
    color VARCHAR(7) DEFAULT '#FF9500',

    -- Indici per performance
    INDEX idx_enc_folder_name (name),
    INDEX idx_enc_folder_created_at (created_at DESC),
    INDEX idx_enc_folder_access_count (access_count DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella file (notevolmente migliorata)
CREATE TABLE IF NOT EXISTS file (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    original_name VARCHAR(255),
    size BIGINT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    folder_id INT NULL,
    enc_id INT NULL,
    file_hash VARCHAR(64),
    mime_type VARCHAR(100),
    download_count INT DEFAULT 0,
    last_modified DATETIME NULL,
    tags TEXT,
    preview_available BOOLEAN DEFAULT FALSE,

    -- Indici per performance
    INDEX idx_file_name (name),
    INDEX idx_file_uploaded_at (uploaded_at DESC),
    INDEX idx_file_hash (file_hash),
    INDEX idx_file_size (size DESC),
    INDEX idx_file_mime_type (mime_type),
    INDEX idx_file_download_count (download_count DESC),

    -- Chiavi esterne con cascade
    FOREIGN KEY (folder_id) REFERENCES folder(id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (enc_id) REFERENCES encrypted_folders(id) ON DELETE CASCADE ON UPDATE CASCADE,

    -- Constraint per integrità
    CONSTRAINT chk_file_folder CHECK (
        (folder_id IS NOT NULL AND enc_id IS NULL) OR 
        (folder_id IS NULL AND enc_id IS NOT NULL)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =======================
-- TABELLE AUDIT E ANALYTICS
-- =======================

-- Tabella audit logs per sicurezza
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_ip VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id INT,
    details TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent VARCHAR(500),

    -- Indici per query veloci
    INDEX idx_audit_timestamp (timestamp DESC),
    INDEX idx_audit_user_ip (user_ip),
    INDEX idx_audit_action (action),
    INDEX idx_audit_resource (resource_type, resource_id),
    INDEX idx_audit_date (DATE(timestamp))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabella statistiche sistema giornaliere
CREATE TABLE IF NOT EXISTS system_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL UNIQUE,
    total_uploads INT DEFAULT 0,
    total_downloads INT DEFAULT 0,
    total_folders_created INT DEFAULT 0,
    total_encrypted_folders_created INT DEFAULT 0,
    disk_usage_bytes BIGINT DEFAULT 0,
    active_users INT DEFAULT 0,
    avg_response_time FLOAT DEFAULT 0.0,

    -- Indici per analytics
    INDEX idx_stats_date (date DESC),
    INDEX idx_stats_uploads (total_uploads DESC),
    INDEX idx_stats_disk_usage (disk_usage_bytes DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =======================
-- TABELLE CACHE E PERFORMANCE
-- =======================

-- Tabella cache per query frequenti
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

-- =======================
-- VIEWS PER ANALYTICS
-- =======================

-- Vista per statistiche cartelle
CREATE OR REPLACE VIEW folder_stats AS
SELECT 
    'normal' as folder_type,
    COUNT(*) as total_count,
    AVG(access_count) as avg_access_count,
    MAX(created_at) as latest_creation,
    SUM(CASE WHEN is_public = TRUE THEN 1 ELSE 0 END) as public_count
FROM folder
UNION ALL
SELECT 
    'encrypted' as folder_type,
    COUNT(*) as total_count,
    AVG(access_count) as avg_access_count,
    MAX(created_at) as latest_creation,
    0 as public_count
FROM encrypted_folders;

-- Vista per statistiche file
CREATE OR REPLACE VIEW file_stats AS
SELECT 
    CASE 
        WHEN folder_id IS NOT NULL THEN 'normal'
        WHEN enc_id IS NOT NULL THEN 'encrypted'
    END as file_type,
    COUNT(*) as total_files,
    SUM(size) as total_size_bytes,
    AVG(size) as avg_size_bytes,
    SUM(download_count) as total_downloads,
    COUNT(DISTINCT CASE 
        WHEN folder_id IS NOT NULL THEN folder_id 
        WHEN enc_id IS NOT NULL THEN enc_id 
    END) as unique_folders
FROM file
WHERE folder_id IS NOT NULL OR enc_id IS NOT NULL
GROUP BY file_type;

-- Vista per audit summary
CREATE OR REPLACE VIEW daily_audit_summary AS
SELECT 
    DATE(timestamp) as audit_date,
    COUNT(*) as total_actions,
    COUNT(DISTINCT user_ip) as unique_users,
    COUNT(DISTINCT action) as unique_actions,
    action as most_common_action,
    COUNT(*) as action_count
FROM audit_logs 
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(timestamp), action
ORDER BY audit_date DESC, action_count DESC;

-- =======================
-- STORED PROCEDURES
-- =======================

-- Procedura per cleanup automatico
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS CleanupOldData()
BEGIN
    -- Cleanup audit logs più vecchi di 30 giorni
    DELETE FROM audit_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY);

    -- Cleanup statistiche più vecchie di 1 anno
    DELETE FROM system_stats 
    WHERE date < DATE_SUB(CURDATE(), INTERVAL 1 YEAR);

    -- Cleanup cache scaduta
    DELETE FROM query_cache 
    WHERE expires_at < NOW();

    -- Ottimizzazione tabelle
    ANALYZE TABLE folder, encrypted_folders, file, audit_logs;

    SELECT 'Cleanup completato' as status;
END //
DELIMITER ;

-- Procedura per statistiche rapide
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS GetSystemOverview()
BEGIN
    DECLARE total_folders INT DEFAULT 0;
    DECLARE total_encrypted_folders INT DEFAULT 0;
    DECLARE total_files INT DEFAULT 0;
    DECLARE total_size BIGINT DEFAULT 0;
    DECLARE total_downloads INT DEFAULT 0;

    SELECT COUNT(*) INTO total_folders FROM folder;
    SELECT COUNT(*) INTO total_encrypted_folders FROM encrypted_folders;
    SELECT COUNT(*), COALESCE(SUM(size), 0), COALESCE(SUM(download_count), 0) 
    INTO total_files, total_size, total_downloads FROM file;

    SELECT 
        total_folders,
        total_encrypted_folders,
        total_files,
        total_size,
        total_downloads,
        NOW() as generated_at;
END //
DELIMITER ;

-- =======================
-- TRIGGERS PER AUTOMAZIONE
-- =======================

-- Trigger per aggiornamento automatico last_accessed su folder
DELIMITER //
CREATE TRIGGER IF NOT EXISTS update_folder_access 
BEFORE UPDATE ON folder
FOR EACH ROW
BEGIN
    IF NEW.access_count > OLD.access_count THEN
        SET NEW.last_accessed = NOW();
    END IF;
END //
DELIMITER ;

-- Trigger per aggiornamento automatico last_accessed su encrypted_folders
DELIMITER //
CREATE TRIGGER IF NOT EXISTS update_encrypted_folder_access 
BEFORE UPDATE ON encrypted_folders
FOR EACH ROW
BEGIN
    IF NEW.access_count > OLD.access_count THEN
        SET NEW.last_accessed = NOW();
    END IF;
END //
DELIMITER ;

-- Trigger per audit automatico su eliminazione file
DELIMITER //
CREATE TRIGGER IF NOT EXISTS audit_file_deletion 
AFTER DELETE ON file
FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (user_ip, action, resource_type, resource_id, details)
    VALUES ('system', 'file_deleted', 'file', OLD.id, 
            CONCAT('File: ', OLD.name, ', Size: ', OLD.size));
END //
DELIMITER ;

-- =======================
-- DATI DI ESEMPIO (OPZIONALI)
-- =======================

-- Inserimento statistiche iniziali
INSERT IGNORE INTO system_stats (date, total_uploads, total_downloads, total_folders_created, total_encrypted_folders_created)
VALUES (CURDATE(), 0, 0, 0, 0);

-- =======================
-- OTTIMIZZAZIONI DATABASE
-- =======================

-- Configurazioni MySQL ottimizzate per IRIS-VE
SET GLOBAL innodb_buffer_pool_size = 134217728;  -- 128MB
SET GLOBAL query_cache_size = 67108864;          -- 64MB
SET GLOBAL query_cache_type = ON;
SET GLOBAL max_connections = 100;
SET GLOBAL innodb_log_file_size = 50331648;      -- 48MB
SET GLOBAL innodb_flush_log_at_trx_commit = 2;   -- Performance boost
SET GLOBAL sync_binlog = 0;                      -- Disabilita per performance

-- Event scheduler per manutenzione automatica
SET GLOBAL event_scheduler = ON;

-- Evento per cleanup automatico giornaliero
CREATE EVENT IF NOT EXISTS daily_cleanup
ON SCHEDULE EVERY 1 DAY
STARTS '2025-09-22 02:00:00'
DO CALL CleanupOldData();

-- =======================
-- SICUREZZA
-- =======================

-- Creazione utente applicazione (raccomandato per produzione)
-- DECOMMENTARE E MODIFICARE PASSWORD IN PRODUZIONE
/*
CREATE USER IF NOT EXISTS 'iris_ve_app'@'localhost' IDENTIFIED BY 'PASSWORD_SICURA_QUI';
GRANT SELECT, INSERT, UPDATE, DELETE ON python.* TO 'iris_ve_app'@'localhost';
GRANT EXECUTE ON python.* TO 'iris_ve_app'@'localhost';
FLUSH PRIVILEGES;
*/

-- =======================
-- VERIFICA INSTALLAZIONE
-- =======================

-- Test integrità dati
SELECT 'Verifica integrità database...' as status;

-- Conta tabelle create
SELECT 
    COUNT(*) as tables_created,
    GROUP_CONCAT(TABLE_NAME) as table_names
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'python' 
AND TABLE_TYPE = 'BASE TABLE';

-- Verifica indici
SELECT 
    TABLE_NAME,
    COUNT(*) as index_count
FROM information_schema.STATISTICS 
WHERE TABLE_SCHEMA = 'python'
GROUP BY TABLE_NAME;

-- Verifica views
SELECT 
    COUNT(*) as views_created,
    GROUP_CONCAT(TABLE_NAME) as view_names
FROM information_schema.VIEWS 
WHERE TABLE_SCHEMA = 'python';

-- Verifica stored procedures
SELECT 
    COUNT(*) as procedures_created,
    GROUP_CONCAT(ROUTINE_NAME) as procedure_names
FROM information_schema.ROUTINES 
WHERE ROUTINE_SCHEMA = 'python' 
AND ROUTINE_TYPE = 'PROCEDURE';

-- Test connessione
SELECT 
    'Database IRIS-VE v2.0 configurato con successo!' as message,
    NOW() as timestamp,
    DATABASE() as current_database,
    USER() as current_user,
    @@version as mysql_version;

-- Fine script
SELECT '✅ Installazione database completata - IRIS-VE v2.0 pronto!' as final_status;

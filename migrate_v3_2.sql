-- ============================================================================
-- IRIS-VE v3.2 — Migration Script
-- Applies to: installazioni esistenti (v2.x / v3.0 / v3.1)
-- Sicuro da eseguire più volte (usa IF NOT EXISTS e check information_schema).
-- ============================================================================
-- Esegui con: mysql -u root -p iris_ve < migrate_v3_2.sql
-- ============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================================
-- 1. Aggiungi colonne personali a users (v3.2)
-- ============================================================================
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'first_name');
SET @s = IF(@col = 0,
    'ALTER TABLE `users` ADD COLUMN `first_name` VARCHAR(100) NULL DEFAULT NULL AFTER `password_hash`',
    'SELECT "users.first_name already exists"');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'last_name');
SET @s = IF(@col = 0,
    'ALTER TABLE `users` ADD COLUMN `last_name` VARCHAR(100) NULL DEFAULT NULL AFTER `first_name`',
    'SELECT "users.last_name already exists"');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'phone');
SET @s = IF(@col = 0,
    'ALTER TABLE `users` ADD COLUMN `phone` VARCHAR(20) NULL DEFAULT NULL AFTER `last_name`',
    'SELECT "users.phone already exists"');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ============================================================================
-- 2. org_roles (da v3.1 — idempotente)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `org_roles` (
    `id`              INT          NOT NULL AUTO_INCREMENT,
    `organization_id` INT          NOT NULL,
    `name`            VARCHAR(100) NOT NULL,
    `permissions`     JSON         NOT NULL,
    `color`           VARCHAR(20)  NOT NULL DEFAULT 'accent',
    `created_at`      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_org_role_name` (`organization_id`, `name`),
    KEY `ix_org_roles_org` (`organization_id`),
    CONSTRAINT `fk_org_roles_org`
        FOREIGN KEY (`organization_id`) REFERENCES `organizations` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 3. Colonne v3.1 su organization_members (idempotente)
-- ============================================================================
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organization_members' AND COLUMN_NAME = 'custom_role_id');
SET @s = IF(@col = 0,
    'ALTER TABLE `organization_members`
        ADD COLUMN `custom_role_id` INT NULL DEFAULT NULL,
        ADD CONSTRAINT `fk_members_role`
            FOREIGN KEY (`custom_role_id`) REFERENCES `org_roles` (`id`) ON DELETE SET NULL',
    'SELECT "organization_members.custom_role_id already exists"');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'organization_members' AND COLUMN_NAME = 'permissions_override');
SET @s = IF(@col = 0,
    'ALTER TABLE `organization_members` ADD COLUMN `permissions_override` JSON NULL DEFAULT NULL',
    'SELECT "organization_members.permissions_override already exists"');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ============================================================================
-- 4. storage_config (idempotente)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `storage_config` (
    `id`               INT          NOT NULL AUTO_INCREMENT,
    `active_disk_path` VARCHAR(512) NOT NULL,
    `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- 5. Verifica
-- ============================================================================
SET FOREIGN_KEY_CHECKS = 1;

SELECT 'Migration v3.2 completata.' AS status;

SELECT
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_DEFAULT
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'users'
  AND COLUMN_NAME IN ('first_name','last_name','phone')
ORDER BY ORDINAL_POSITION;

SELECT
    TABLE_NAME,
    TABLE_ROWS
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN ('users','org_roles','storage_config','organization_members')
ORDER BY TABLE_NAME;


-- ============================================================================
-- IRIS-VE v3.1 — Migration Script
-- Applies to: existing databases created with database_setup.sql (v2.x)
-- Run ONCE on existing installations.
-- Safe to run multiple times (uses IF NOT EXISTS / column existence checks).
-- ============================================================================

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- ============================================================================
-- 1. Create org_roles table
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
        FOREIGN KEY (`organization_id`)
        REFERENCES `organizations` (`id`)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- 2. Add columns to organization_members (safe: only if not already present)
-- ============================================================================
-- custom_role_id
SET @col_exists = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'organization_members'
      AND COLUMN_NAME  = 'custom_role_id'
);
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE `organization_members`
        ADD COLUMN `custom_role_id` INT NULL,
        ADD CONSTRAINT `fk_members_role`
            FOREIGN KEY (`custom_role_id`)
            REFERENCES `org_roles` (`id`)
            ON DELETE SET NULL',
    'SELECT "custom_role_id already exists"'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- permissions_override
SET @col_exists2 = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'organization_members'
      AND COLUMN_NAME  = 'permissions_override'
);
SET @sql2 = IF(@col_exists2 = 0,
    'ALTER TABLE `organization_members` ADD COLUMN `permissions_override` JSON NULL',
    'SELECT "permissions_override already exists"'
);
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;


-- ============================================================================
-- 3. Create storage_config table
-- ============================================================================
CREATE TABLE IF NOT EXISTS `storage_config` (
    `id`               INT          NOT NULL AUTO_INCREMENT,
    `active_disk_path` VARCHAR(512) NOT NULL,
    `updated_at`       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================================================
-- 4. Verify
-- ============================================================================
SELECT 'Migration v3.1 completed successfully.' AS status;

SELECT
    TABLE_NAME,
    TABLE_ROWS,
    CREATE_TIME
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN ('org_roles', 'storage_config', 'organization_members')
ORDER BY TABLE_NAME;


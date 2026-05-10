CREATE DATABASE IF NOT EXISTS dns;
USE dns;

CREATE TABLE IF NOT EXISTS dns_domain_stats (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    stat_date DATE NOT NULL,
    stat_hour TINYINT NOT NULL,
    access_count BIGINT NOT NULL DEFAULT 0,
    UNIQUE KEY uk_domain_time (domain, stat_date, stat_hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `security_rules` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',
    `rule_type` varchar(32) NOT NULL COMMENT '规则类型: client_ip, target_ip, domain',
    `rule_value` varchar(255) NOT NULL COMMENT '规则值: CIDR或域名',
    `is_enabled` tinyint(1) NOT NULL DEFAULT '1' COMMENT '是否启用: 1启用, 0禁用',
    `description` varchar(255) DEFAULT '' COMMENT '规则描述/备注(如: 拦截恶意广告)',
    `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
    PRIMARY KEY (`id`),
    -- 核心优化：组合索引。查询时我们只关心“已启用”的规则，并且按类型区分
    KEY `idx_enabled_type` (`is_enabled`, `rule_type`),
    -- 唯一索引：防止手抖插入重复的规则
    UNIQUE KEY `uk_type_value` (`rule_type`, `rule_value`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='DNS安全拦截规则表';

-- 插入几条测试数据
INSERT INTO `security_rules` (`rule_type`, `rule_value`, `description`) VALUES 
('client_ip', '192.168.1.0/24', '测试拦截网段'),
('domain', 'ads.google.com.', '拦截谷歌广告'),
('domain', 'badguy.net.', '拦截恶意域名'),
('target_ip', '10.255.255.254/32', '拦截特定解析目标IP');
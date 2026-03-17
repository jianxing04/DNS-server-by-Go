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
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Upstream UpstreamConfig `yaml:"upstream"`
	MySQL    MySQLConfig    `yaml:"mysql"`
	Redis    RedisConfig    `yaml:"redis"`
	Cache    CacheConfig    `yaml:"cache"`
	Worker   WorkerConfig   `yaml:"worker"`
}

type ServerConfig struct {
	Listen         string `yaml:"listen"`
	MetricsAddr    string `yaml:"metrics_addr"`
	SocketPoolSize int    `yaml:"socket_pool_size"`
}

type UpstreamConfig struct {
	Servers []string `yaml:"servers"`
	Timeout string   `yaml:"timeout"`
}

func (u UpstreamConfig) TimeoutDuration() time.Duration {
	d, err := time.ParseDuration(u.Timeout)
	if err != nil {
		return 200 * time.Millisecond
	}
	return d
}

type MySQLConfig struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	User               string `yaml:"user"`
	Password           string `yaml:"password"`
	Database           string `yaml:"database"`
	Charset            string `yaml:"charset"`
	MaxOpenConns       int    `yaml:"max_open_conns"`
	MaxIdleConns       int    `yaml:"max_idle_conns"`
	RuleSyncInterval   string `yaml:"rule_sync_interval"`
	StatsFlushInterval string `yaml:"stats_flush_interval"`
}

func (m MySQLConfig) RuleSyncDuration() time.Duration {
	d, err := time.ParseDuration(m.RuleSyncInterval)
	if err != nil {
		return 1 * time.Minute
	}
	return d
}

func (m MySQLConfig) StatsFlushDuration() time.Duration {
	d, err := time.ParseDuration(m.StatsFlushInterval)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

func (m MySQLConfig) DSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s&parseTime=true&loc=Local",
		m.User, m.Password, m.Host, m.Port, m.Database, m.Charset)
}

type RedisConfig struct {
	Addr         string `yaml:"addr"`
	Password     string `yaml:"password"`
	DB           int    `yaml:"db"`
	PoolSize     int    `yaml:"pool_size"`
	MinIdleConns int    `yaml:"min_idle_conns"`
	DialTimeout  string `yaml:"dial_timeout"`
	ReadTimeout  string `yaml:"read_timeout"`
	WriteTimeout string `yaml:"write_timeout"`
	PoolTimeout  string `yaml:"pool_timeout"`
}

func (r RedisConfig) DialTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(r.DialTimeout)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

func (r RedisConfig) ReadTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(r.ReadTimeout)
	if err != nil {
		return 1 * time.Second
	}
	return d
}

func (r RedisConfig) WriteTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(r.WriteTimeout)
	if err != nil {
		return 1 * time.Second
	}
	return d
}

func (r RedisConfig) PoolTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(r.PoolTimeout)
	if err != nil {
		return 2 * time.Second
	}
	return d
}

type CacheConfig struct {
	LocalCacheSize   int    `yaml:"local_cache_size"`
	WriteQueueSize   int    `yaml:"write_queue_size"`
	MinWorkers       int    `yaml:"min_workers"`
	MaxWorkers       int    `yaml:"max_workers"`
	ScaleUpThreshold int    `yaml:"scale_up_threshold"`
	ScaleDownIdle    string `yaml:"scale_down_idle"`
}

func (c CacheConfig) ScaleDownIdleDuration() time.Duration {
	d, err := time.ParseDuration(c.ScaleDownIdle)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

type WorkerConfig struct {
	JobQueueSize int    `yaml:"job_queue_size"`
	MinWorkers   int    `yaml:"min_workers"`
	MaxWorkers   int    `yaml:"max_workers"`
	IdleTimeout  string `yaml:"idle_timeout"`
}

func (w WorkerConfig) IdleTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(w.IdleTimeout)
	if err != nil {
		return 10 * time.Minute
	}
	return d
}

func Load(path string) (*Config, error) {
	cfg := &Config{}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败 %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("解析配置文件失败: %w", err)
		}
	}

	applyDefaults(cfg)
	applyEnvOverrides(cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DNS_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("DNS_METRICS_ADDR"); v != "" {
		cfg.Server.MetricsAddr = v
	}
	if v := os.Getenv("DNS_SOCKET_POOL_SIZE"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.SocketPoolSize)
	}
	if v := os.Getenv("DNS_UPSTREAM_TIMEOUT"); v != "" {
		cfg.Upstream.Timeout = v
	}
	if v := os.Getenv("MYSQL_HOST"); v != "" {
		cfg.MySQL.Host = v
	}
	if v := os.Getenv("MYSQL_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.MySQL.Port)
	}
	if v := os.Getenv("MYSQL_USER"); v != "" {
		cfg.MySQL.User = v
	}
	if v := os.Getenv("MYSQL_PASSWORD"); v != "" {
		cfg.MySQL.Password = v
	}
	if v := os.Getenv("MYSQL_DATABASE"); v != "" {
		cfg.MySQL.Database = v
	}
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		cfg.Redis.Addr = v
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("CACHE_SIZE"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Cache.LocalCacheSize)
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:8053"
	}
	if cfg.Server.MetricsAddr == "" {
		cfg.Server.MetricsAddr = ":2112"
	}
	if cfg.Server.SocketPoolSize == 0 {
		cfg.Server.SocketPoolSize = 1000
	}
	if cfg.Upstream.Timeout == "" {
		cfg.Upstream.Timeout = "200ms"
	}
	if cfg.MySQL.Host == "" {
		cfg.MySQL.Host = "127.0.0.1"
	}
	if cfg.MySQL.Port == 0 {
		cfg.MySQL.Port = 3306
	}
	if cfg.MySQL.Charset == "" {
		cfg.MySQL.Charset = "utf8mb4"
	}
	if cfg.MySQL.MaxOpenConns == 0 {
		cfg.MySQL.MaxOpenConns = 50
	}
	if cfg.MySQL.MaxIdleConns == 0 {
		cfg.MySQL.MaxIdleConns = 10
	}
	if cfg.MySQL.RuleSyncInterval == "" {
		cfg.MySQL.RuleSyncInterval = "1m"
	}
	if cfg.MySQL.StatsFlushInterval == "" {
		cfg.MySQL.StatsFlushInterval = "10s"
	}
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "localhost:6379"
	}
	if cfg.Redis.PoolSize == 0 {
		cfg.Redis.PoolSize = 500
	}
	if cfg.Redis.MinIdleConns == 0 {
		cfg.Redis.MinIdleConns = 50
	}
	if cfg.Redis.DialTimeout == "" {
		cfg.Redis.DialTimeout = "5s"
	}
	if cfg.Redis.ReadTimeout == "" {
		cfg.Redis.ReadTimeout = "1s"
	}
	if cfg.Redis.WriteTimeout == "" {
		cfg.Redis.WriteTimeout = "1s"
	}
	if cfg.Redis.PoolTimeout == "" {
		cfg.Redis.PoolTimeout = "2s"
	}
	if cfg.Cache.LocalCacheSize == 0 {
		cfg.Cache.LocalCacheSize = 100 * 1024 * 1024 // 100MB
	}
	if cfg.Cache.WriteQueueSize == 0 {
		cfg.Cache.WriteQueueSize = 50000
	}
	if cfg.Cache.MinWorkers == 0 {
		cfg.Cache.MinWorkers = 10
	}
	if cfg.Cache.MaxWorkers == 0 {
		cfg.Cache.MaxWorkers = 1000
	}
	if cfg.Cache.ScaleUpThreshold == 0 {
		cfg.Cache.ScaleUpThreshold = 1000
	}
	if cfg.Cache.ScaleDownIdle == "" {
		cfg.Cache.ScaleDownIdle = "30s"
	}
	if cfg.Worker.JobQueueSize == 0 {
		cfg.Worker.JobQueueSize = 10000
	}
	if cfg.Worker.MinWorkers == 0 {
		cfg.Worker.MinWorkers = 5
	}
	if cfg.Worker.MaxWorkers == 0 {
		cfg.Worker.MaxWorkers = 100000
	}
	if cfg.Worker.IdleTimeout == "" {
		cfg.Worker.IdleTimeout = "10m"
	}
}

package auth

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Audiences      []string                 `yaml:"audiences"`
	CacheTTL       time.Duration            `yaml:"cache_ttl"`
	CacheSize      int                      `yaml:"cache_size"`
	RequestTimeout time.Duration            `yaml:"request_timeout"`
	Clusters       map[string]ClusterConfig `yaml:"clusters"`
}

type ClusterConfig struct {
	APIServer string `yaml:"api_server"`
	JWKSURL   string `yaml:"jwks_url"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"`
}

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	var cfg Config
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err := d.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.Audiences) == 0 {
		return fmt.Errorf("at least one audience is required")
	}
	for _, audience := range c.Audiences {
		if strings.TrimSpace(audience) != audience || audience == "" {
			return fmt.Errorf("audiences must be nonempty without surrounding whitespace")
		}
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.RequestTimeout < time.Millisecond || c.RequestTimeout > time.Minute {
		return fmt.Errorf("request_timeout must be between 1ms and 1m")
	}
	if len(c.Clusters) == 0 || len(c.Clusters) > 32 {
		return fmt.Errorf("between 1 and 32 clusters are required")
	}
	if c.CacheTTL < 0 || c.CacheTTL > time.Minute {
		return fmt.Errorf("cache_ttl must be between 0 and 1m")
	}
	if c.CacheSize == 0 {
		c.CacheSize = 1000
	}
	if c.CacheSize < 1 || c.CacheSize > 10000 {
		return fmt.Errorf("cache_size must be between 1 and 10000")
	}
	for id, cluster := range c.Clusters {
		if strings.TrimSpace(id) != id || id == "" || cluster.TokenFile == "" {
			return fmt.Errorf("each cluster requires a stable ID and token_file")
		}
		if len(c.Clusters) > 1 && cluster.JWKSURL == "" {
			return fmt.Errorf("cluster %q requires jwks_url for federation", id)
		}
		if cluster.JWKSURL != "" {
			api, _ := url.Parse(cluster.APIServer)
			keys, _ := url.Parse(cluster.JWKSURL)
			if !validEndpoint(cluster.JWKSURL) || api == nil || keys.Scheme != api.Scheme || keys.Host != api.Host {
				return fmt.Errorf("cluster %q jwks_url must use the api_server HTTPS origin", id)
			}
		}
		if !validEndpoint(cluster.APIServer) {
			return fmt.Errorf("cluster %q requires an HTTPS api_server without credentials, query or fragment", id)
		}
	}
	return nil
}

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

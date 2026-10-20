package auth

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	RenewalInterval time.Duration            `yaml:"renewal_interval"`
	Persistence     *PersistenceConfig       `yaml:"persistence"`
	Audiences       []string                 `yaml:"audiences"`
	CacheTTL        time.Duration            `yaml:"cache_ttl"`
	CacheSize       int                      `yaml:"cache_size"`
	RequestTimeout  time.Duration            `yaml:"request_timeout"`
	Clusters        map[string]ClusterConfig `yaml:"clusters"`
}

type ClusterConfig struct {
	Renewal   *RenewalConfig `yaml:"renewal"`
	APIServer string         `yaml:"api_server"`
	JWKSURL   string         `yaml:"jwks_url"`
	CAFile    string         `yaml:"ca_file"`
	TokenFile string         `yaml:"token_file"`
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
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return cfg, fmt.Errorf("authentication config must contain one YAML document")
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
	if c.RenewalInterval == 0 {
		c.RenewalInterval = time.Minute
	}
	if c.RenewalInterval < time.Second || c.RenewalInterval > time.Hour {
		return fmt.Errorf("renewal_interval must be between 1s and 1h")
	}
	managed := false
	for id, cluster := range c.Clusters {
		if strings.TrimSpace(id) != id || id == "" || cluster.TokenFile == "" {
			return fmt.Errorf("each cluster requires a stable ID and token_file")
		}
		if r := cluster.Renewal; r != nil {
			managed = true
			if !resourceName(id) || !resourceName(r.Namespace) || !resourceName(r.ServiceAccount) || len(r.Audiences) == 0 {
				return fmt.Errorf("cluster %q renewal requires valid names and reviewer audiences", id)
			}
			for _, a := range r.Audiences {
				if strings.TrimSpace(a) != a || a == "" {
					return fmt.Errorf("invalid reviewer audience")
				}
			}
			if r.TokenDuration == 0 {
				r.TokenDuration = time.Hour
			}
			if r.RenewBefore == 0 {
				r.RenewBefore = 10 * time.Minute
			}
			if r.TokenDuration < 10*time.Minute || r.TokenDuration > 30*24*time.Hour || r.RenewBefore <= 0 || r.RenewBefore >= r.TokenDuration {
				return fmt.Errorf("invalid renewal duration or threshold")
			}
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
	if p := c.Persistence; p != nil {
		if !managed || !validEndpoint(p.APIServer) || p.TokenFile == "" || !resourceName(p.Namespace) || !resourceName(p.Secret) {
			return fmt.Errorf("persistence requires managed renewal, an HTTPS API, token_file, namespace and Secret name")
		}
	}
	return nil
}

var resourcePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

func resourceName(value string) bool { return len(value) <= 63 && resourcePattern.MatchString(value) }

func validEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

package config

import (
	"fmt"
	"os"

	"github.com/stretchr/testify/assert/yaml"
)

type Config struct {
	Server       string `yaml:"server"`
	ListenAddr   string `yaml:"listen"`
	UDPEnabled   bool   `yaml:"udp"`
	DecoyTraffic bool   `yaml:"decoy-traffic"`

	Torrent struct {
		AuthKey            string `yaml:"auth-key"`
		InfoHash           string `yaml:"info-hash"`
		SessionsNum        int    `yaml:"sessions-num"`
		ConnectionsTimeOut int    `yaml:"connections-time-out"`
	} `yaml:"torrent"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	cfg := &Config{
		
	}

	cfg.ListenAddr = "0.0.0.0:1080"
	cfg.UDPEnabled = true
	cfg.DecoyTraffic = false

	cfg.Torrent.SessionsNum = 5
	cfg.Torrent.ConnectionsTimeOut = 60

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required in config")
	}

	return cfg, nil
}

package config

import (
	importRand "crypto/rand"
	"encoding/hex"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port string `yaml:"port"`

	Torrent struct {
		AuthKey  string `yaml:"auth-key"`
		InfoHash string `yaml:"info-hash"`
	} `yaml:"torrent"`
}

func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return createDefaultConfig(path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func createDefaultConfig(path string) (*Config, error) {
	// Генерация ключей для дефолтного конфига
	authKeyBytes := make([]byte, 32)
	importRand.Read(authKeyBytes)

	infoHashBytes := make([]byte, 20)
	importRand.Read(infoHashBytes)

	cfg := &Config{
		Port: "50000-50100",
	}
	cfg.Torrent.AuthKey = hex.EncodeToString(authKeyBytes)
	cfg.Torrent.InfoHash = hex.EncodeToString(infoHashBytes)

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, err
	}

	return cfg, nil
}

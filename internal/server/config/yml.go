package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func parseYML(c *Config) error {
	f, err := os.Open(c.FileStoragePath)
	if err != nil {
		return fmt.Errorf("config: failed to open file: %w", err)
	}
	defer f.Close()

	if err := yaml.NewDecoder(f).Decode(c); err != nil {
		return fmt.Errorf("config: failed to decode file: %w", err)
	}

	return nil
}

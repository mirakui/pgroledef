package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Decode parses canonical JSON strictly: unknown fields are rejected so that
// typos in jsonnet surface before anything touches a database.
func Decode(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode canonical config: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode canonical config: trailing data after document")
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	d := DefaultPolicyFor(c.Target.Engine)
	if c.Policy.Authoritative == nil {
		c.Policy.Authoritative = d.Authoritative
	}
	if c.Policy.ProtectedRoles == nil {
		c.Policy.ProtectedRoles = d.ProtectedRoles
	}
	if c.Policy.UnmanagedDatabases == nil {
		c.Policy.UnmanagedDatabases = d.UnmanagedDatabases
	}
}

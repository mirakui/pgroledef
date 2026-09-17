// Package config defines the canonical (flat, catalog-aligned) model that
// pgroledef consumes after jsonnet evaluation, and validates it.
package config

import (
	"fmt"
	"strings"
)

type Engine string

const (
	EngineAuroraPostgres Engine = "aurora-postgresql"
	EngineDSQL           Engine = "dsql"
)

type Privilege string

const (
	PrivSelect     Privilege = "SELECT"
	PrivInsert     Privilege = "INSERT"
	PrivUpdate     Privilege = "UPDATE"
	PrivDelete     Privilege = "DELETE"
	PrivTruncate   Privilege = "TRUNCATE"
	PrivReferences Privilege = "REFERENCES"
	PrivTrigger    Privilege = "TRIGGER"
	PrivUsage      Privilege = "USAGE"
	PrivCreate     Privilege = "CREATE"
	PrivConnect    Privilege = "CONNECT"
	PrivTemp       Privilege = "TEMPORARY"
)

var allPrivileges = map[Privilege]bool{
	PrivSelect: true, PrivInsert: true, PrivUpdate: true, PrivDelete: true,
	PrivTruncate: true, PrivReferences: true, PrivTrigger: true,
	PrivUsage: true, PrivCreate: true, PrivConnect: true, PrivTemp: true,
}

// Config is the canonical document. Field names are the JSON wire format.
type Config struct {
	Version           int                `json:"version"`
	Target            Target             `json:"target"`
	Policy            Policy             `json:"policy"`
	Roles             map[string]Role    `json:"roles"`
	Grants            []Grant            `json:"grants"`
	DefaultPrivileges []DefaultPrivilege `json:"default_privileges"`
}

type Target struct {
	Engine     Engine `json:"engine"`
	Identifier string `json:"identifier"`
}

type Policy struct {
	Authoritative      *bool    `json:"authoritative"`
	ProtectedRoles     []string `json:"protected_roles"`
	UnmanagedDatabases []string `json:"unmanaged_databases"`
}

type Role struct {
	Login            bool              `json:"login"`
	MemberOf         []string          `json:"member_of,omitempty"`
	IAM              *IAM              `json:"iam,omitempty"`
	Settings         map[string]string `json:"settings,omitempty"`
	CreatesObjectsIn []string          `json:"creates_objects_in,omitempty"`
}

type IAM struct {
	Enabled    bool     `json:"enabled"`
	Principals []string `json:"principals,omitempty"`
}

// GrantTarget is a tagged union: exactly one field must be set.
type GrantTarget struct {
	Database             string `json:"database,omitempty"`
	Schema               string `json:"schema,omitempty"`
	AllTablesInSchema    string `json:"all_tables_in_schema,omitempty"`
	AllSequencesInSchema string `json:"all_sequences_in_schema,omitempty"`
	Table                string `json:"table,omitempty"`
	Sequence             string `json:"sequence,omitempty"`
}

type Grant struct {
	On         GrantTarget `json:"on"`
	To         string      `json:"to"`
	Privileges []Privilege `json:"privileges"`
}

type ObjectKind string

const (
	ObjTables    ObjectKind = "tables"
	ObjSequences ObjectKind = "sequences"
)

type DefaultPrivilege struct {
	ForRole    string      `json:"for_role"`
	InSchema   string      `json:"in_schema"`
	On         ObjectKind  `json:"on"`
	To         string      `json:"to"`
	Privileges []Privilege `json:"privileges"`
}

// DefaultPolicy returns the policy defaults applied when a field is omitted.
func DefaultPolicy() Policy {
	t := true
	return Policy{
		Authoritative:      &t,
		ProtectedRoles:     []string{"postgres", "rdsadmin", "rds_*", "pg_*", "admin"},
		UnmanagedDatabases: []string{"postgres", "rdsadmin", "template*"},
	}
}

// QualifiedSchema is "database.schema".
type QualifiedSchema struct{ Database, Schema string }

func (q QualifiedSchema) String() string { return q.Database + "." + q.Schema }

// QualifiedRelation is "database.schema.relation".
type QualifiedRelation struct{ Database, Schema, Name string }

func (q QualifiedRelation) String() string { return q.Database + "." + q.Schema + "." + q.Name }

func (q QualifiedRelation) SchemaRef() QualifiedSchema {
	return QualifiedSchema{Database: q.Database, Schema: q.Schema}
}

func ParseSchema(s string) (QualifiedSchema, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return QualifiedSchema{}, fmt.Errorf("schema %q must be \"database.schema\"", s)
	}
	return QualifiedSchema{Database: parts[0], Schema: parts[1]}, nil
}

func ParseRelation(s string) (QualifiedRelation, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return QualifiedRelation{}, fmt.Errorf("relation %q must be \"database.schema.name\"", s)
	}
	return QualifiedRelation{Database: parts[0], Schema: parts[1], Name: parts[2]}, nil
}

// Kind reports which union member of GrantTarget is set, and its value.
func (t GrantTarget) Kind() (string, string, error) {
	var kind, val string
	n := 0
	set := func(k, v string) {
		if v != "" {
			n++
			kind, val = k, v
		}
	}
	set("database", t.Database)
	set("schema", t.Schema)
	set("all_tables_in_schema", t.AllTablesInSchema)
	set("all_sequences_in_schema", t.AllSequencesInSchema)
	set("table", t.Table)
	set("sequence", t.Sequence)
	if n != 1 {
		return "", "", fmt.Errorf("grant target must set exactly one of database/schema/all_tables_in_schema/all_sequences_in_schema/table/sequence, got %d", n)
	}
	return kind, val, nil
}

{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x', postgres_version: 16 }, policy: {},
  roles: [{ name: 'app', grants: [{ on: { all_tables_in_schema: 'db.public' }, privileges: ['SELECT', 'MAINTAIN'] }] }] }

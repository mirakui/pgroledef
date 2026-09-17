{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: { app: {} }, grants: [{ on: { database: 'db' }, to: 'app', privileges: [] }], default_privileges: [] }

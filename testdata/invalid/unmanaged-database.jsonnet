{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: { app: {} }, grants: [{ on: { database: 'postgres' }, to: 'app', privileges: ['CONNECT'] }], default_privileges: [] }

{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: { app: {} }, grants: [{ on: { schema: 'db.public' }, to: 'app', privileges: ['SELECT'] }], default_privileges: [] }

{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app' }], grants: [{ on: { schema: 'db.public' }, to: 'app', privileges: ['SELECT'] }], default_privileges: [] }

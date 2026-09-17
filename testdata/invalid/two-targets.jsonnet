{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app' }], grants: [{ on: { database: 'db', schema: 'db.public' }, to: 'app', privileges: ['CONNECT'] }], default_privileges: [] }

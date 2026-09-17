{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', grants: [{ on: { schema: 'db.public' }, privileges: ['SELECT'] }] }] }

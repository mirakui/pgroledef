{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', grants: [{ on: { database: 'postgres' }, privileges: ['CONNECT'] }] }] }

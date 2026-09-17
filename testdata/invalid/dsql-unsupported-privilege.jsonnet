{ version: 1, target: { engine: 'dsql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', login: true,
            grants: [{ on: { table: 'postgres.app.jobs' }, privileges: ['TRUNCATE'] }] }] }

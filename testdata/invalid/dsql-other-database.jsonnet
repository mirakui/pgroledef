{ version: 1, target: { engine: 'dsql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', login: true,
            grants: [{ on: { schema: 'app.public' }, privileges: ['USAGE'] }] }] }

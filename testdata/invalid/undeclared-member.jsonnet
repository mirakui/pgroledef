{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', login: true, member_of: ['grp_missing'] }] }

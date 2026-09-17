{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'viewer', default_privileges: [{ for_role: 'ghost', in_schema: 'db.public', on: 'tables', privileges: ['SELECT'] }] }] }

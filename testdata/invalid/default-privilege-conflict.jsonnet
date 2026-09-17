{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: { viewer: {}, mig: { login: true, creates_objects_in: ['db.public'] } },
  grants: [{ on: { all_tables_in_schema: 'db.public' }, to: 'viewer', privileges: ['SELECT'] }],
  default_privileges: [{ for_role: 'mig', in_schema: 'db.public', on: 'tables', to: 'viewer', privileges: ['SELECT', 'INSERT'] }] }

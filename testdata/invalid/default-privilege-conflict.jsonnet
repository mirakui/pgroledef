{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [
    { name: 'mig', login: true, creates_objects_in: ['db.public'] },
    { name: 'viewer',
      grants: [{ on: { all_tables_in_schema: 'db.public' }, privileges: ['SELECT'] }],
      default_privileges: [{ for_role: 'mig', in_schema: 'db.public', on: 'tables', privileges: ['SELECT', 'INSERT'] }] },
  ] }

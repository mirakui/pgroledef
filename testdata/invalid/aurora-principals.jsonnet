{ version: 1, target: { engine: 'aurora-postgresql', identifier: 'x' }, policy: {},
  roles: [{ name: 'app', login: true, iam: { enabled: true, principals: ['arn:aws:iam::123456789012:role/App'] } }],
  grants: [], default_privileges: [] }

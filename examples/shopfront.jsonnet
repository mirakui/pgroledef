// Example: roles for a fictional e-commerce application ("shopfront") on Aurora PostgreSQL.
// Evaluate with: pgroledef render -f examples/shopfront.jsonnet --ext-str env=staging
//
// Role layout:
//   grp_shopfront_reader / grp_shopfront_writer  NOLOGIN permission groups
//   shopfront_migrator   runs schema migrations (IAM auth) and therefore owns the tables
//   shopfront_api        the application server (IAM auth)
//   shopfront_worker*    background workers using a rotated password (two users
//                        for alternating-user rotation), limited to the job queue
//   bi_readonly          a BI tool with a static password, production only
local env = std.extVar('env');
local db = 'shopfront';
local schema = db + '.public';
local workers = ['shopfront_worker', 'shopfront_worker_clone'];

{
  version: 1,
  target: { engine: 'aurora-postgresql', identifier: env + '-shopfront' },
  policy: {},

  roles: [
    { name: 'grp_shopfront_reader' },
    { name: 'grp_shopfront_writer', member_of: ['grp_shopfront_reader'] },

    // Tables are created by the migration role, so every schema-wide grant
    // below is also turned into ALTER DEFAULT PRIVILEGES FOR ROLE shopfront_migrator.
    {
      name: 'shopfront_migrator',
      login: true,
      member_of: ['grp_shopfront_writer'],
      iam: { enabled: true },
      creates_objects_in: [schema],
    },
    { name: 'shopfront_api', login: true, member_of: ['grp_shopfront_writer'], iam: { enabled: true } },
  ] + [
    // Passwords are managed elsewhere (e.g. a secrets manager); pgroledef only
    // guarantees the roles exist with LOGIN.
    { name: w, login: true }
    for w in workers
  ] + (if env == 'production' then [
    { name: 'bi_readonly', login: true, member_of: ['grp_shopfront_reader'] },
  ] else []),

  grants: [
    { on: { database: db }, to: 'grp_shopfront_reader', privileges: ['CONNECT'] },
    { on: { schema: schema }, to: 'grp_shopfront_reader', privileges: ['USAGE'] },
    { on: { schema: schema }, to: 'grp_shopfront_writer', privileges: ['USAGE', 'CREATE'] },
    { on: { all_tables_in_schema: schema }, to: 'grp_shopfront_reader', privileges: ['SELECT'] },
    { on: { all_tables_in_schema: schema }, to: 'grp_shopfront_writer', privileges: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
    { on: { all_sequences_in_schema: schema }, to: 'grp_shopfront_writer', privileges: ['USAGE', 'SELECT'] },
  ] + std.flattenArrays([
    [
      { on: { database: db }, to: w, privileges: ['CONNECT'] },
      { on: { schema: schema }, to: w, privileges: ['USAGE'] },
      { on: { table: schema + '.job_queue' }, to: w, privileges: ['SELECT', 'INSERT', 'UPDATE'] },
    ]
    for w in workers
  ]),

  default_privileges: [],
}

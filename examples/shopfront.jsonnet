// Example: roles for a fictional e-commerce application ("shopfront") on Aurora PostgreSQL.
// Evaluate with: pgroledef render -f examples/shopfront.jsonnet --ext-str env=staging
//
// Role layout:
//   grp_shopfront_reader / grp_shopfront_writer  NOLOGIN permission groups
//   shopfront_migrator   runs schema migrations (IAM auth via rds_iam) and therefore owns the tables
//   shopfront_api        the application server (IAM auth via rds_iam)
//   shopfront_worker*    background workers using a rotated password (two users
//                        for alternating-user rotation), limited to the job queue
//   bi_readonly          a BI tool with a static password, production only
local env = std.extVar('env');
local db = 'shopfront';
local schema = db + '.public';

// Both worker users need identical privileges for alternating-user rotation.
local workerGrants = [
  { on: { database: db }, privileges: ['CONNECT'] },
  { on: { schema: schema }, privileges: ['USAGE'] },
  { on: { table: schema + '.job_queue' }, privileges: ['SELECT', 'INSERT', 'UPDATE'] },
];

{
  version: 1,
  target: { engine: 'aurora-postgresql', identifier: env + '-shopfront' },
  policy: {},

  roles: [
    {
      name: 'grp_shopfront_reader',
      grants: [
        { on: { database: db }, privileges: ['CONNECT'] },
        { on: { schema: schema }, privileges: ['USAGE'] },
        { on: { all_tables_in_schema: schema }, privileges: ['SELECT'] },
      ],
    },
    {
      name: 'grp_shopfront_writer',
      member_of: ['grp_shopfront_reader'],
      grants: [
        { on: { schema: schema }, privileges: ['USAGE', 'CREATE'] },
        { on: { all_tables_in_schema: schema }, privileges: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
        { on: { all_sequences_in_schema: schema }, privileges: ['USAGE', 'SELECT'] },
      ],
    },

    // Tables are created by the migration role, so every schema-wide grant
    // above is also turned into ALTER DEFAULT PRIVILEGES FOR ROLE shopfront_migrator.
    {
      name: 'shopfront_migrator',
      login: true,
      member_of: ['grp_shopfront_writer', 'rds_iam'],
      creates_objects_in: [schema],
    },
    { name: 'shopfront_api', login: true, member_of: ['grp_shopfront_writer', 'rds_iam'] },

    // Passwords are managed elsewhere (e.g. a secrets manager); pgroledef only
    // guarantees the roles exist with LOGIN.
    { name: 'shopfront_worker', login: true, grants: workerGrants },
    { name: 'shopfront_worker_clone', login: true, grants: workerGrants },
  ] + (if env == 'production' then [
    { name: 'bi_readonly', login: true, member_of: ['grp_shopfront_reader'] },
  ] else []),
}

// Example: the same "shopfront" application on Aurora DSQL.
// Evaluate with:
//   pgroledef render -f examples/shopfront-dsql.jsonnet \
//     --ext-str env=staging --ext-str account=012345678901
//
// Differences from examples/shopfront.jsonnet (Aurora PostgreSQL):
//   - a DSQL cluster has exactly one database, always named "postgres", so
//     every identifier starts with it and there are no ON DATABASE grants
//   - environments are separated by schema rather than by database
//   - IAM identities are mapped in the database with AWS IAM GRANT
//     (iam_principals) instead of through rds_iam membership
local env = std.extVar('env');
local account = std.extVar('account');
local schema = 'postgres.shopfront_' + env;
local iamRole(name) = 'arn:aws:iam::' + account + ':role/shopfront-' + env + '-' + name;

{
  version: 1,
  target: { engine: 'dsql', identifier: env + '-shopfront' },
  policy: {},

  roles: [
    {
      name: 'grp_shopfront_reader',
      grants: [
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

    // The migration role creates the tables, so the schema-wide grants above
    // are also turned into ALTER DEFAULT PRIVILEGES FOR ROLE shopfront_migrator.
    {
      name: 'shopfront_migrator',
      login: true,
      member_of: ['grp_shopfront_writer'],
      creates_objects_in: [schema],
      iam_principals: [iamRole('migrator')],
    },
    {
      name: 'shopfront_api',
      login: true,
      member_of: ['grp_shopfront_writer'],
      iam_principals: [iamRole('api')],
    },
  ] + (if env == 'production' then [
         { name: 'bi_readonly', login: true, member_of: ['grp_shopfront_reader'], iam_principals: [iamRole('bi')] },
       ] else []),
}

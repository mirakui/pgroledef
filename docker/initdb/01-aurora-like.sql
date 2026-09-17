-- Emulate the parts of an Aurora PostgreSQL cluster that pgroledef relies on.
-- Aurora ships these roles; plain PostgreSQL does not.
CREATE ROLE rds_iam;
CREATE ROLE rds_superuser;
CREATE ROLE rdsadmin;

-- Databases and schemas are out of pgroledef's scope, so the fixture creates them.
CREATE DATABASE shopfront;

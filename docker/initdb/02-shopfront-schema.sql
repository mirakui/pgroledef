\c shopfront
-- In real life these come from the application's migrations. The fixture
-- creates a few tables as postgres so the example grants have targets.
CREATE TABLE customers (id bigserial PRIMARY KEY, email text NOT NULL);
CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id bigint REFERENCES customers, total_cents bigint NOT NULL);
CREATE TABLE job_queue (id bigserial PRIMARY KEY, kind text NOT NULL, status text NOT NULL);

CREATE TABLE verification_budget (id smallint PRIMARY KEY CHECK(id=1),day date NOT NULL,accepted integer NOT NULL,rejected bigint NOT NULL);
CREATE TABLE verification_destinations (destination_hash text PRIMARY KEY,next_allowed_at timestamptz NOT NULL);

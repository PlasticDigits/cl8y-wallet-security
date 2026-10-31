CREATE TABLE controller_fanout (
 event_id text PRIMARY KEY REFERENCES security_events(id), cursor uuid, completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);

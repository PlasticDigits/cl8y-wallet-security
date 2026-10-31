ALTER TABLE notification_outbox ADD COLUMN lease_id uuid;
CREATE TABLE chain_receipts (
 chain_id text NOT NULL, height bigint NOT NULL, tx_hash text NOT NULL, event_index integer NOT NULL,
 contract text NOT NULL, semantic_id text NOT NULL, PRIMARY KEY(chain_id,tx_hash,event_index)
);

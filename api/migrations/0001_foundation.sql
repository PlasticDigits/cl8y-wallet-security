CREATE TABLE profiles (
 id uuid PRIMARY KEY, anchor_wallet text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now(),
 assignment_delay_seconds integer NOT NULL DEFAULT 86400 CHECK (assignment_delay_seconds >= 86400)
);
CREATE TABLE wallets (
 address text PRIMARY KEY, profile_id uuid NOT NULL REFERENCES profiles(id), verified_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sessions (
 token_hash text PRIMARY KEY, profile_id uuid NOT NULL REFERENCES profiles(id), csrf_token text NOT NULL,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE challenges (
 id uuid PRIMARY KEY, address text NOT NULL, purpose text NOT NULL, profile_id uuid REFERENCES profiles(id),
 message text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX challenge_rate ON challenges(address, created_at);
CREATE TABLE assignments (
 id uuid PRIMARY KEY, profile_id uuid NOT NULL REFERENCES profiles(id), owner_wallet text NOT NULL,
 candidate_wallet text NOT NULL, role text NOT NULL CHECK (role IN ('guardian','recovery','notification')),
 proposed_at timestamptz NOT NULL DEFAULT now(), executable_at timestamptz NOT NULL,
 delay_seconds integer NOT NULL CHECK (delay_seconds >= 86400), accepted_at timestamptz,
 cancelled_at timestamptz, removal_at timestamptz, CHECK (candidate_wallet <> owner_wallet)
);
CREATE INDEX assignments_profile ON assignments(profile_id);
CREATE TABLE contacts (
 id uuid PRIMARY KEY, profile_id uuid NOT NULL REFERENCES profiles(id), kind text NOT NULL CHECK(kind IN ('email','telegram')),
 encrypted_destination bytea NOT NULL, verified_at timestamptz, removal_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz
);
CREATE TABLE contact_verifications (
 token_hash text PRIMARY KEY, contact_id uuid NOT NULL REFERENCES contacts(id), expires_at timestamptz NOT NULL,
 used_at timestamptz, attempts integer NOT NULL DEFAULT 0
);
CREATE TABLE security_events (
 id text PRIMARY KEY, profile_id uuid REFERENCES profiles(id), action text NOT NULL,
 wallet text NOT NULL, token text, proposed_at timestamptz NOT NULL, executable_at timestamptz NOT NULL,
 chain_id text, block_height bigint, tx_hash text, event_index integer,
 created_at timestamptz NOT NULL DEFAULT now(), CHECK (executable_at >= proposed_at)
);
CREATE TABLE notification_outbox (
 id uuid PRIMARY KEY, event_id text NOT NULL REFERENCES security_events(id), contact_id uuid NOT NULL REFERENCES contacts(id),
 template text NOT NULL DEFAULT 'timer_start', state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','sending','sent','failed','blocked')),
 attempts integer NOT NULL DEFAULT 0, next_attempt_at timestamptz NOT NULL DEFAULT now(), locked_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz, last_error_code text,
 UNIQUE(event_id,contact_id,template)
);
CREATE INDEX outbox_due ON notification_outbox(state,next_attempt_at);
CREATE TABLE chain_checkpoints (
 chain_id text PRIMARY KEY, height bigint NOT NULL, block_hash text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE worker_heartbeats (
 name text PRIMARY KEY, last_seen timestamptz NOT NULL, source_sha text NOT NULL, detail jsonb NOT NULL
);

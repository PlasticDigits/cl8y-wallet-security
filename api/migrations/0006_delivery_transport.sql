-- Persist the transport used at the first attempted send. SMTP has no idempotency
-- primitive; provider switches and worker restarts must not replay an ambiguous send.
ALTER TABLE notification_outbox ADD COLUMN delivery_transport text
    CHECK (delivery_transport IN ('resend','smtp','telegram'));
-- The preceding reviewed source supported only Resend and Telegram.
UPDATE notification_outbox o SET delivery_transport = CASE c.kind
    WHEN 'email' THEN 'resend' ELSE 'telegram' END
FROM contacts c WHERE c.id=o.contact_id AND o.attempts>0;

-- One-time operator migration for rows written before replay minimization.
-- Back up first and run during a maintenance window: this rewrites every
-- decision row, including old caller_scope IS NULL rows, and generates WAL.
-- Header values, body, extra, IP, referrer, timestamp and TLS fields are
-- discarded. The response payload and linked feedback are not modified.
-- A path or user agent may still contain personal data. Follow this with
-- the separately scheduled retention purge described in INSTALL.md.

BEGIN;

UPDATE mcp_decisions AS decision
SET request_payload = jsonb_build_object(
    'user_agent', decision.request_payload->'user_agent',
    'path', decision.request_payload->'path',
    'method', decision.request_payload->'method',
    'headers',
        CASE
            WHEN jsonb_typeof(decision.request_payload->'headers') = 'object'
            THEN
                (CASE WHEN EXISTS (
                    SELECT 1
                    FROM jsonb_object_keys(decision.request_payload->'headers') AS header(name)
                    WHERE lower(header.name) = 'accept'
                ) THEN '{"accept":""}'::jsonb ELSE '{}'::jsonb END)
                ||
                (CASE WHEN EXISTS (
                    SELECT 1
                    FROM jsonb_object_keys(decision.request_payload->'headers') AS header(name)
                    WHERE lower(header.name) = 'accept-language'
                ) THEN '{"accept-language":""}'::jsonb ELSE '{}'::jsonb END)
            ELSE 'null'::jsonb
        END
)
WHERE jsonb_typeof(decision.request_payload) = 'object';

COMMIT;

-- VACUUM cannot run inside the transaction. Arrange ordinary VACUUM/backup
-- and WAL retention separately; a SQL UPDATE does not erase old physical bytes.

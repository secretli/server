-- Write your migrate up statements here
create table "secrets" (
    public_id text primary key,
    retrieval_token text not null,
    nonce text not null,
    encrypted_data text not null,
    expires_at timestamptz not null
);

---- create above / drop below ----

-- Write your migrate down statements here. If this migration is irreversible
-- Then delete the separator line above
drop table if exists "secrets";

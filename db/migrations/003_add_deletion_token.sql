-- Write your migrate up statements here
alter table if exists secrets
add column if not exists deletion_token text;

---- create above / drop below ----

-- Write your migrate down statements here. If this migration is irreversible
-- Then delete the separator line above.
alter table if exists secrets
drop column if exists deletion_token;

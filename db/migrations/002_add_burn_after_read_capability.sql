-- Write your migrate up statements here
alter table if exists secrets
add column if not exists burn_after_read boolean not null default false,
add column if not exists already_read boolean not null default false;

---- create above / drop below ----

-- Write your migrate down statements here. If this migration is irreversible
-- Then delete the separator line above.
alter table if exists secrets
drop column if exists burn_after_read,
drop column if exists  already_read;

-- Core users/auth
create table if not exists users (
    user_id bigint primary key,
    phone text unique not null,
    first_name text not null default '',
    last_name text not null default '',
    created_at timestamptz not null default now()
);

create table if not exists auth_credentials (
    user_id bigint primary key references users(user_id),
    password_hash text,
    phone_code_hash text,
    phone_code_sent_at timestamptz
);

create table if not exists auth_keys (
    auth_key_id bigint primary key,
    user_id bigint references users(user_id),
    key_fingerprint bytea not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz
);

create table if not exists sessions (
    session_id bigint primary key,
    auth_key_id bigint not null references auth_keys(auth_key_id),
    user_id bigint references users(user_id),
    server_salt bigint not null,
    layer int not null default 0,
    is_online boolean not null default false,
    updated_at timestamptz not null default now()
);

-- Chats/dialogs/messages
create table if not exists chats (
    chat_id bigint primary key,
    title text not null,
    is_group boolean not null default true,
    created_by bigint not null references users(user_id),
    created_at timestamptz not null default now()
);

create table if not exists chat_members (
    chat_id bigint not null references chats(chat_id),
    user_id bigint not null references users(user_id),
    joined_at timestamptz not null default now(),
    primary key (chat_id, user_id)
);

create table if not exists dialogs (
    dialog_id bigint primary key,
    owner_user_id bigint not null references users(user_id),
    peer_id bigint not null,
    is_group boolean not null,
    created_at timestamptz not null default now()
);

create table if not exists messages (
    message_id bigint primary key,
    dialog_id bigint not null references dialogs(dialog_id),
    from_user_id bigint not null references users(user_id),
    message_text text not null,
    date_unix bigint not null,
    created_at timestamptz not null default now()
);

create table if not exists message_deletions (
    dialog_id bigint not null references dialogs(dialog_id),
    message_id bigint not null references messages(message_id),
    deleted_by bigint not null references users(user_id),
    deleted_at timestamptz not null default now(),
    primary key (dialog_id, message_id)
);

-- Profile and update state
create table if not exists user_profiles (
    user_id bigint primary key references users(user_id),
    bio text not null default '',
    updated_at timestamptz not null default now()
);

create table if not exists update_state (
    user_id bigint not null references users(user_id),
    session_id bigint references sessions(session_id),
    pts int not null default 0,
    qts int not null default 0,
    seq int not null default 0,
    state_date_unix bigint not null default 0,
    primary key (user_id, session_id)
);
-- Phone verification codes with TTL
create table if not exists phone_codes (
    phone text primary key,
    code text not null,
    hash text not null,
    expires_at timestamptz not null
);

-- Unified ID allocator so services can mint IDs without cross-service calls
create table if not exists id_sequences (
    name text primary key,
    next_val bigint not null default 1
);

insert into id_sequences (name, next_val) values
    ('user_id', 1000),
    ('chat_id', 3000),
    ('dialog_id', 2000),
    ('message_id', 4000)
on conflict (name) do nothing;

-- PTS-ordered update log for getDifference
create table if not exists user_pts_updates (
    id bigserial primary key,
    user_id bigint not null references users(user_id),
    pts int not null,
    update_type text not null,
    update_data jsonb not null default '{}',
    date_unix bigint not null
);
create index if not exists idx_pts_updates_user_pts on user_pts_updates (user_id, pts);

-- Add random_id for message idempotency
alter table messages add column if not exists random_id bigint;
create unique index if not exists idx_messages_random_id on messages (from_user_id, random_id) where random_id is not null;

-- Per-user message deletions (revoke vs personal)
alter table message_deletions add column if not exists deleted_for_user_id bigint references users(user_id);
-- Migrate existing rows: set deleted_for_user_id = deleted_by where null
update message_deletions set deleted_for_user_id = deleted_by where deleted_for_user_id is null;
-- Drop old PK and create new one
alter table message_deletions drop constraint if exists message_deletions_pkey;
alter table message_deletions add primary key (message_id, deleted_for_user_id);

-- Read inbox tracking on dialogs
alter table dialogs add column if not exists read_inbox_max_id bigint not null default 0;

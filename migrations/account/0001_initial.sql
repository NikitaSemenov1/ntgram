create table if not exists users (
    user_id    bigint primary key,
    phone      text unique not null,
    first_name text not null default '',
    last_name  text not null default '',
    username   text,
    created_at timestamptz not null default now()
);

create unique index if not exists users_username_unique
    on users (username)
    where username is not null;

create table if not exists auth_credentials (
    user_id            bigint primary key references users(user_id),
    password_hash      text,
    phone_code_hash    text,
    phone_code_sent_at timestamptz
);

create table if not exists auth_keys (
    auth_key_id     numeric primary key,
    user_id         bigint references users(user_id),
    key_fingerprint bytea not null,
    created_at      timestamptz not null default now(),
    expires_at      timestamptz
);

create table if not exists sessions (
    session_id  numeric primary key,
    auth_key_id numeric not null references auth_keys(auth_key_id),
    user_id     bigint references users(user_id),
    server_salt bigint not null,
    layer       int    not null default 0,
    updated_at  timestamptz not null default now()
);

create table if not exists user_profiles (
    user_id    bigint primary key references users(user_id),
    bio        text not null default '',
    updated_at timestamptz not null default now()
);

create table if not exists phone_codes (
    phone      text primary key,
    code       text not null,
    hash       text not null,
    expires_at timestamptz not null
);

create table if not exists id_sequences (
    name     text   primary key,
    next_val bigint not null default 1
);

insert into id_sequences (name, next_val) values
    ('user_id', 1000)
on conflict (name) do nothing;

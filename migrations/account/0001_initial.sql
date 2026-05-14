create table if not exists users (
    user_id    bigint primary key,
    phone      text unique not null,
    first_name text not null default '',
    last_name  text not null default '',
    username   text,
    bio        text not null default '',
    created_at timestamptz not null default now(),
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

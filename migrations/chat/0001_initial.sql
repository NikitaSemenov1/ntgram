create table if not exists chats (
    chat_id            bigint  primary key,
    title              text    not null,
    is_group           boolean not null default true,
    created_by         bigint  not null,
    created_at         timestamptz not null default now(),
    version            integer not null default 1,
    participants_count integer not null default 0,
    date_unix          bigint  not null default 0
);

create table if not exists chat_members (
    chat_id         bigint not null references chats(chat_id),
    user_id         bigint not null,
    inviter_user_id bigint not null default 0,
    joined_at       timestamptz not null default now(),
    primary key (chat_id, user_id)
);

create table if not exists dialogs (
    dialog_id               bigint  not null,
    owner_user_id           bigint  not null,
    peer_id                 bigint  not null,
    is_group                boolean not null,
    created_at              timestamptz not null default now(),
    read_inbox_max_id       bigint  not null default 0,
    read_outbox_max_id      bigint  not null default 0,
    unread_count            int     not null default 0,
    top_user_message_box_id bigint  not null default 0,
    top_message_date        bigint  not null default 0,
    primary key (dialog_id, owner_user_id)
);

create table if not exists message_boxes (
    user_id             bigint   not null,
    user_message_box_id bigint   not null,
    dialog_message_id   bigint   not null,
    dialog_id           bigint   not null,
    peer_type           smallint not null,
    peer_id             bigint   not null,
    from_user_id        bigint   not null,
    out                 boolean  not null,
    random_id           bigint,
    text                text     not null default '',
    entities            jsonb,
    read                boolean  not null default false,
    mentioned           boolean  not null default false,
    media_unread        boolean  not null default false,
    deleted             boolean  not null default false,
    edit_date           bigint   not null default 0,
    pts                 int      not null default 0,
    date_unix           bigint   not null,
    primary key (user_id, user_message_box_id)
);

create unique index if not exists idx_message_boxes_random_id
    on message_boxes (user_id, random_id)
    where random_id is not null;

create table if not exists id_sequences (
    name     text   primary key,
    next_val bigint not null default 1
);

insert into id_sequences (name, next_val) values
    ('chat_id',           3000),
    ('dialog_id',         2000),
    ('dialog_message_id', 5000)
on conflict (name) do nothing;

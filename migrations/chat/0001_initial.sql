create table if not exists chats (
    chat_id            bigint  primary key,
    title              text    not null,
    created_by         bigint  not null,
    created_at         timestamptz not null default now(),
    version            integer not null default 1,
    participants_count integer not null default 0,
    date_unix          bigint  not null default 0
);

create table if not exists threads (
    thread_id  bigint     primary key,
    chat_id    bigint     references chats(chat_id),
    created_at timestamptz not null default now()
);

create table if not exists thread_participants (
    thread_id       bigint not null references threads(thread_id),
    user_id         bigint not null,
    inviter_user_id bigint not null default 0,
    joined_at       timestamptz not null default now(),
    primary key (thread_id, user_id)
);

create table if not exists dialog_state (
    thread_id               bigint  not null references threads(thread_id),
    owner_user_id           bigint  not null,
    peer_user_id            bigint,
    peer_chat_id            bigint  references chats(chat_id),
    read_inbox_max_id       bigint  not null default 0,
    read_outbox_max_id      bigint  not null default 0,
    unread_count            int     not null default 0,
    top_user_message_box_id bigint  not null default 0,
    created_at              timestamptz not null default now(),
    primary key (thread_id, owner_user_id),
    check (
        (peer_user_id is not null and peer_chat_id is null)
        or (peer_user_id is null and peer_chat_id is not null)
    )
);

create table if not exists messages (
    dialog_message_id bigint primary key,
    thread_id         bigint not null references threads(thread_id),
    from_user_id      bigint not null,
    text              text   not null default '',
    entities          jsonb,
    date_unix         bigint not null,
    edit_date         bigint not null default 0
);

create table if not exists message_boxes (
    user_id             bigint  not null,
    user_message_box_id bigint  not null,
    dialog_message_id   bigint  not null references messages(dialog_message_id),
    out                 boolean not null,
    random_id           bigint,
    read                boolean not null default false,
    deleted             boolean not null default false,
    pts                 int     not null default 0,
    primary key (user_id, user_message_box_id)
);

create table if not exists chat_events (
    event_id        bigserial primary key,
    chat_id         bigint not null references chats(chat_id),
    actor_user_id   bigint not null,
    kind            text   not null,
    payload         jsonb  not null default '{}'::jsonb,
    date_unix       bigint not null
);

create table if not exists id_sequences (
    name     text   primary key,
    next_val bigint not null default 1
);

insert into id_sequences (name, next_val) values
    ('chat_id',           3000),
    ('thread_id',         2000),
    ('dialog_message_id', 5000)
on conflict (name) do nothing;

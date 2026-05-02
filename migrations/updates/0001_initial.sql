create table if not exists update_state (
    user_id         bigint not null,
    session_id      bigint not null,
    pts             int    not null default 0,
    qts             int    not null default 0,
    seq             int    not null default 0,
    state_date_unix bigint not null default 0,
    primary key (user_id, session_id)
);

create table if not exists user_pts_updates (
    id          bigserial primary key,
    user_id     bigint    not null,
    pts         int       not null,
    pts_count   int       not null default 1,
    update_type text      not null,
    update_data jsonb     not null default '{}',
    date_unix   bigint    not null
);

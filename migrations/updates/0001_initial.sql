create table if not exists update_state (
    user_id         bigint primary key,
    pts             int    not null default 0,
    state_date_unix bigint not null default 0
);

create table if not exists user_pts_updates (
    id          bigserial primary key,
    user_id     bigint    not null,
    pts         int       not null,
    update_type text      not null,
    update_data jsonb     not null default '{}',
    date_unix   bigint    not null
);

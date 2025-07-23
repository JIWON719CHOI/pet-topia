# 회원
CREATE TABLE member
(
    id          VARCHAR(255) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    email       VARCHAR(255) NULL,
    name        VARCHAR(255) NOT NULL,
    nick_name   VARCHAR(255) NOT NULL UNIQUE,
    info        VARCHAR(255) NULL,
    inserted_at datetime     NOT NULL DEFAULT NOW(),
    CONSTRAINT pk_member PRIMARY KEY (id)
);
# 원래 있는 테이블 ,., 
create table prj4.member
(
    email       varchar(255)                         not null
        primary key,
    password    varchar(255)                         not null,
    nick_name   varchar(255)                         not null,
    info        varchar(3000)                        null,
    inserted_at datetime default current_timestamp() not null,
    constraint nick_name
        unique (nick_name)
);


# 연습 회원
CREATE TABLE member1
(
    id          VARCHAR(255) NOT NULL,
    username    VARCHAR(255) NOT NULL,
    password    VARCHAR(255) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    nick_name   VARCHAR(255) NOT NULL UNIQUE,
    info        VARCHAR(255) NULL,
    inserted_at datetime     NOT NULL DEFAULT NOW(),
    social_type VARCHAR(255) NOT NULL,
    social_id   VARCHAR(255) NOT NULL,
    CONSTRAINT pk_member1 PRIMARY KEY (id)
);

ALTER TABLE member1
    ADD CONSTRAINT uc_member1_username UNIQUE (username);
DROP TABLE member1;

SHOW VARIABLES LIKE 'max_connections';
SHOW PROCESSLIST;
SHOW COLUMNS FROM member;
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
# 원래 있는 테이블 ,., ㅠ

# 연습 회원
CREATE TABLE member1
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
DROP TABLE member;

SHOW VARIABLES LIKE 'max_connections';
SHOW PROCESSLIST;
SHOW COLUMNS FROM member;
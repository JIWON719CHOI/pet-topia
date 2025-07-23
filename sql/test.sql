CREATE SCHEMA test;
DROP SCHEMA test;
# 테스트
CREATE TABLE users
(
    id       INT AUTO_INCREMENT NOT NULL,
    email    VARCHAR(255)       NOT NULL UNIQUE,
    name     VARCHAR(255)       NULL,
    provider VARCHAR(255)       NULL,
    CONSTRAINT pk_users PRIMARY KEY (id)
);

# 걍 위에 UNIQUE 추가
# ALTER TABLE users
#     ADD CONSTRAINT uc_users_email UNIQUE (email);
SHOW FULL COLUMNS FROM users;
ALTER TABLE users
    MODIFY name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
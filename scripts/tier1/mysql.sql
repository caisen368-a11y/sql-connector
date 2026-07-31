CREATE DATABASE IF NOT EXISTS connector_e2e
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

CREATE USER IF NOT EXISTS 'connector'@'localhost' IDENTIFIED BY 'connector-ci-password';
CREATE USER IF NOT EXISTS 'connector'@'127.0.0.1' IDENTIFIED BY 'connector-ci-password';
CREATE USER IF NOT EXISTS 'connector'@'%' IDENTIFIED BY 'connector-ci-password';
ALTER USER 'connector'@'localhost' IDENTIFIED BY 'connector-ci-password';
ALTER USER 'connector'@'127.0.0.1' IDENTIFIED BY 'connector-ci-password';
ALTER USER 'connector'@'%' IDENTIFIED BY 'connector-ci-password';
GRANT ALL PRIVILEGES ON connector_e2e.* TO 'connector'@'localhost';
GRANT ALL PRIVILEGES ON connector_e2e.* TO 'connector'@'127.0.0.1';
GRANT ALL PRIVILEGES ON connector_e2e.* TO 'connector'@'%';

CREATE USER IF NOT EXISTS 'tier1_client_identity_secret'@'localhost' REQUIRE X509;
CREATE USER IF NOT EXISTS 'tier1_client_identity_secret'@'127.0.0.1' REQUIRE X509;
CREATE USER IF NOT EXISTS 'tier1_client_identity_secret'@'%' REQUIRE X509;
ALTER USER 'tier1_client_identity_secret'@'localhost' REQUIRE X509;
ALTER USER 'tier1_client_identity_secret'@'127.0.0.1' REQUIRE X509;
ALTER USER 'tier1_client_identity_secret'@'%' REQUIRE X509;
GRANT SELECT ON connector_e2e.* TO 'tier1_client_identity_secret'@'localhost';
GRANT SELECT ON connector_e2e.* TO 'tier1_client_identity_secret'@'127.0.0.1';
GRANT SELECT ON connector_e2e.* TO 'tier1_client_identity_secret'@'%';

USE connector_e2e;

CREATE TABLE owners (
    id BIGINT NOT NULL,
    CONSTRAINT owners_pkey PRIMARY KEY (id)
) ENGINE = InnoDB COMMENT = 'Tier-1 fixture owners';

CREATE TABLE items (
    id BIGINT NOT NULL COMMENT 'Tier-1 fixture item identifier',
    owner_id BIGINT NULL,
    name VARCHAR(255) NOT NULL,
    qty BIGINT NOT NULL,
    metadata JSON NOT NULL,
    payload TEXT NULL,
    CONSTRAINT items_pkey PRIMARY KEY (id),
    CONSTRAINT items_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES owners (id),
    CONSTRAINT items_name_key UNIQUE (name),
    INDEX items_qty_idx (qty)
) ENGINE = InnoDB COMMENT = 'Tier-1 fixture items';

INSERT IGNORE INTO owners (id) VALUES (1);

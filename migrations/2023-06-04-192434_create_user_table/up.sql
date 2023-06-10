CREATE TABLE users
(
    id                      SERIAL PRIMARY KEY,
    uuid_id                    VARCHAR(50) UNIQUE  NOT NULL,
    email                   VARCHAR(100) UNIQUE NOT NULL,
    phone                   VARCHAR(20) UNIQUE,
    username                VARCHAR(100) UNIQUE NOT NULL,
    password                VARCHAR(100)        NOT NULL,
    confirmed_email         BOOLEAN                      DEFAULT false,
    confirm_email_token     INTEGER,
    confirmed_phone         BOOLEAN                      DEFAULT false,
    confirm_phone_token     INTEGER,
    current_available_funds INTEGER             NOT NULL DEFAULT 0,
    created_at              TIMESTAMP WITH TIME ZONE     DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP WITH TIME ZONE     DEFAULT CURRENT_TIMESTAMP
);
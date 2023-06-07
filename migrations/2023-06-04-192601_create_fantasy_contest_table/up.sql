CREATE TABLE fantasy_contest
(
    id                    SERIAL PRIMARY KEY,
    uuid                  VARCHAR(50) UNIQUE NOT NULL,
    user_id               INTEGER     NOT NULL,
    player_ids            TEXT        NOT NULL,
    week_of_year          INTEGER     NOT NULL,
    stake                 INTEGER     NOT NULL,
    status                VARCHAR(50) NOT NULL     DEFAULT 'NOT_CHALLENGED',
    date_lock_in          VARCHAR(15),
    challenger_id         INTEGER,
    challenger_stake      INTEGER,
    challenger_player_ids TEXT,
    winner_id             VARCHAR(50),
    expired               INTEGER     NOT NULL     DEFAULT 0,
    created_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (challenger_id) REFERENCES users (id)
);
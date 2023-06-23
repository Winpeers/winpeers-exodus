// @generated automatically by Diesel CLI.

diesel::table! {
    countries (id) {
        id -> Int4,
        uuid -> Varchar,
        name -> Varchar,
        flag -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    fantasy_contest (id) {
        id -> Int4,
        uuid_id -> Varchar,
        user_id -> Int4,
        player_ids -> Text,
        week_of_year -> Int4,
        stake -> Int4,
        status -> Varchar,
        date_lock_in -> Nullable<Varchar>,
        challenger_id -> Nullable<Int4>,
        challenger_stake -> Nullable<Int4>,
        challenger_player_ids -> Nullable<Text>,
        winner_id -> Nullable<Varchar>,
        expired -> Int4,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    fixtures (id) {
        id -> Int4,
        uuid -> Varchar,
        season_id -> Int4,
        unique_id -> Varchar,
        fixture_id -> Varchar,
        week_of_year -> Int4,
        match_status -> Nullable<Varchar>,
        match_finished -> Nullable<Bool>,
        match_time -> Nullable<Varchar>,
        date -> Timestamp,
        home_team -> Varchar,
        away_team -> Varchar,
        home_score -> Nullable<Int4>,
        away_score -> Nullable<Int4>,
        home_score_half_time -> Nullable<Int4>,
        away_score_half_time -> Nullable<Int4>,
        match_information -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
        player_stat_processed -> Nullable<Bool>,
    }
}

diesel::table! {
    leagues (id) {
        id -> Int4,
        uuid -> Varchar,
        country_id -> Int4,
        name -> Varchar,
        flag -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    player_seasonal_data (id) {
        id -> Int4,
        uuid -> Varchar,
        season_id -> Int4,
        player_id -> Int4,
        league_id -> Int4,
        team_id -> Int4,
        age -> Nullable<Varchar>,
        jersey_number -> Int4,
        position_played -> Varchar,
        appearances -> Int4,
        goals -> Int4,
        yellow_cards -> Int4,
        red_cards -> Int4,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    players (id) {
        id -> Int4,
        uuid -> Varchar,
        country_id -> Int4,
        unique_id -> Varchar,
        name -> Nullable<Varchar>,
        name_hash -> Varchar,
        nationality -> Varchar,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    players_per_match_performance (id) {
        id -> Int4,
        uuid -> Varchar,
        player_id -> Int4,
        season_id -> Int4,
        fixture_unique_id -> Varchar,
        date -> Timestamp,
        shots_total -> Int4,
        shot_on_target -> Int4,
        key_pass_total -> Int4,
        pass_success_in_match -> Varchar,
        duel_aerial_won -> Int4,
        touches -> Int4,
        rating -> Numeric,
        minutes_played -> Int4,
        straight_red_card -> Int4,
        double_yellow_red_card -> Int4,
        yellow_card -> Int4,
        goal -> Int4,
        own_goal -> Int4,
        assist -> Int4,
        penalty_missed -> Int4,
        penalty_scored -> Int4,
        penalty_saved -> Int4,
        tackle_won_total -> Int4,
        interception_all -> Int4,
        clearance_total -> Int4,
        shot_blocked -> Int4,
        foul_committed -> Int4,
        dribble_won -> Int4,
        foul_given -> Int4,
        offside_given -> Int4,
        dispossessed -> Int4,
        turnover -> Int4,
        total_passes -> Int4,
        pass_cross_total -> Int4,
        pass_cross_accurate -> Int4,
        pass_long_ball_total -> Int4,
        pass_long_ball_accurate -> Int4,
        pass_through_ball_total -> Int4,
        pass_through_ball_accurate -> Int4,
        custom_fantasy_point -> Int4,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    seasons (id) {
        id -> Int4,
        uuid -> Varchar,
        season -> Varchar,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    team_seasonal_data (id) {
        id -> Int4,
        uuid -> Varchar,
        season_id -> Int4,
        team_id -> Int4,
        position_on_table -> Int4,
        matches_played -> Int4,
        wins -> Int4,
        loses -> Int4,
        draws -> Int4,
        goals_for -> Int4,
        goals_against -> Int4,
        points -> Int4,
        coach -> Varchar,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    teams (id) {
        id -> Int4,
        uuid -> Varchar,
        country_id -> Int4,
        league_id -> Int4,
        name -> Varchar,
        flag -> Nullable<Varchar>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        uuid_id -> Varchar,
        email -> Varchar,
        phone -> Nullable<Varchar>,
        username -> Varchar,
        password -> Varchar,
        confirmed_email -> Nullable<Bool>,
        confirm_email_token -> Nullable<Int4>,
        confirmed_phone -> Nullable<Bool>,
        confirm_phone_token -> Nullable<Int4>,
        reset_password_token -> Nullable<Int4>,
        reset_password_tokenizer -> Nullable<Varchar>,
        current_available_funds -> Int4,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(fixtures -> seasons (season_id));
diesel::joinable!(leagues -> countries (country_id));
diesel::joinable!(player_seasonal_data -> leagues (league_id));
diesel::joinable!(player_seasonal_data -> players (player_id));
diesel::joinable!(player_seasonal_data -> seasons (season_id));
diesel::joinable!(player_seasonal_data -> teams (team_id));
diesel::joinable!(players -> countries (country_id));
diesel::joinable!(players_per_match_performance -> players (player_id));
diesel::joinable!(players_per_match_performance -> seasons (season_id));
diesel::joinable!(team_seasonal_data -> seasons (season_id));
diesel::joinable!(team_seasonal_data -> teams (team_id));
diesel::joinable!(teams -> countries (country_id));
diesel::joinable!(teams -> leagues (league_id));

diesel::allow_tables_to_appear_in_same_query!(
    countries,
    fantasy_contest,
    fixtures,
    leagues,
    player_seasonal_data,
    players,
    players_per_match_performance,
    seasons,
    team_seasonal_data,
    teams,
    users,
);

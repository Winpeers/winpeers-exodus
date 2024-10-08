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

diesel::allow_tables_to_appear_in_same_query!(
    countries,
    fantasy_contest,
    users,
);

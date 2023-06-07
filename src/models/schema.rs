// @generated automatically by Diesel CLI.

diesel::table! {
    fantasy_contest (id) {
        id -> Int4,
        uuid -> Varchar,
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
    todos (id) {
        id -> Varchar,
        title -> Varchar,
        description -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        uuid -> Varchar,
        email -> Varchar,
        phone -> Nullable<Varchar>,
        username -> Varchar,
        password -> Varchar,
        confirmed_email -> Nullable<Bool>,
        confirm_email_token -> Nullable<Int4>,
        confirmed_phone -> Nullable<Bool>,
        confirm_phone_token -> Nullable<Int4>,
        current_available_funds -> Int4,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    fantasy_contest,
    todos,
    users,
);

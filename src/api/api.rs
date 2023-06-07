use actix_web::{HttpResponse, web, post, get, put, delete};
use actix_web::web::{Data, Json};
use crate::models::todo::Todo;
use crate::repository::database::Database;

#[post("/todos")]
pub async fn create_todo(db: Data<Database>, new_todo: Json<Todo>) -> HttpResponse {
    let todo = db.create_todo(new_todo.into_inner()).await;
    match todo {
        Ok(todo) => HttpResponse::Ok().json(todo),
        Err(err) => {
            let error_msg = format!("Internal Server Error: {}", err);
            HttpResponse::InternalServerError().body(error_msg)
        }
    }
}

#[get("/todos")]
pub async fn get_todos(db: web::Data<Database>) -> HttpResponse {
    let todos = db.get_todos().await;
    match todos {
        Ok(todos) => HttpResponse::Ok().json(todos),
        Err(err) => {
            let error_msg = format!("Internal Server Error: {}", err);
            HttpResponse::InternalServerError().body(error_msg)
        }
    }

}
//
#[get("/todos/{id}")]
pub async fn get_todos_by_id(db: web::Data<Database>, id: web::Path<String>) -> HttpResponse {
    let todo = db.get_todos_by_id(&id).await;
    match todo {
        Some(todo) => HttpResponse::Ok().json(todo),
        None => HttpResponse::NotFound().body("Todo not found")
    }
}
//
#[put("/todos/{id}")]
pub async fn update_todo_by_id(db: web::Data<Database>, id: web::Path<String>, updated_todo: Json<Todo>) -> HttpResponse {
    let todo = db.update_todo_by_id(&id, updated_todo.into_inner()).await;
    match todo {
        Some(todo) => HttpResponse::Ok().json(todo),
        None => HttpResponse::NotFound().body("Could not find Todo to update")
    }
}

#[delete("/todos/{id}")]
pub async fn delete_todo_by_id(db: web::Data<Database>, id: web::Path<String>) -> HttpResponse {
    let todo = db.delete_todo_by_id(&id).await;
    match todo {
        Some(todo) => HttpResponse::Ok().json(todo),
        None => HttpResponse::NotFound().body("Could not find Todo to delete")
    }
}

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(create_todo)
            .service(get_todos)
            .service(get_todos_by_id)
            .service(update_todo_by_id)
            .service(delete_todo_by_id)
    );
}
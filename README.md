# Практическое занятие 9. Реализация регистрации и входа пользователей. Хэширование паролей с bcrypt
# Свидовский М.А. ЭФМО-01-25

## Структура проекта
<img width="259" height="475" alt="image" src="https://github.com/user-attachments/assets/92116b0f-a586-451b-9c09-d9d8e42bb8a7" />

## Успешная регистрация и повторная попытка

<img width="1659" height="460" alt="image" src="https://github.com/user-attachments/assets/b49d6823-a2dd-4657-bebc-d559df696810" />

<img width="1657" height="442" alt="image" src="https://github.com/user-attachments/assets/000153eb-0cb2-4e31-a3df-a80d3417af5f" />

## Вход с верными и неверными данными (не говорим что именно не так, выводим общее описание ошибки)

<img width="1659" height="454" alt="image" src="https://github.com/user-attachments/assets/1ee83abf-e4ff-4ea1-9c60-469a4c8281b7" />

<img width="1657" height="465" alt="image" src="https://github.com/user-attachments/assets/f88c1e24-1226-499c-b8d9-dad192c8e87a" />

<img width="1659" height="454" alt="image" src="https://github.com/user-attachments/assets/53425c0c-1d34-4d92-8baf-aef3e4c2bf1e" />

## Фрагменты кода

### Обработчик Register (internal\http\handlers\auth.go)
``` bash
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
    var in registerReq
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        writeErr(w, http.StatusBadRequest, "invalid_json"); return
    }
    in.Email = strings.TrimSpace(strings.ToLower(in.Email))
    if in.Email == "" || len(in.Password) < 8 {
        writeErr(w, http.StatusBadRequest, "email_required_and_password_min_8"); return
    }

    // bcrypt hash
    hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), h.BcryptCost)
    if err != nil {
        writeErr(w, http.StatusInternalServerError, "hash_failed"); return
    }

    u := core.User{Email: in.Email, PasswordHash: string(hash)}
    if err := h.Users.Create(r.Context(), &u); err != nil {
        if err == repo.ErrEmailTaken {
            writeErr(w, http.StatusConflict, "email_taken"); return
        }
        writeErr(w, http.StatusInternalServerError, "db_error"); return
    }

    writeJSON(w, http.StatusCreated, authResp{
        Status: "ok",
        User:   map[string]any{"id": u.ID, "email": u.Email},
    })
}
```

### Обработчик Login (internal\http\handlers\auth.go)
``` bash
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var in loginReq
    if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
        writeErr(w, http.StatusBadRequest, "invalid_json"); return
    }
    in.Email = strings.TrimSpace(strings.ToLower(in.Email))
    if in.Email == "" || in.Password == "" {
        writeErr(w, http.StatusBadRequest, "email_and_password_required"); return
    }

    u, err := h.Users.ByEmail(context.Background(), in.Email)
    if err != nil {
        // не раскрываем, что именно не так
        writeErr(w, http.StatusUnauthorized, "invalid_credentials"); return
    }

    if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
        writeErr(w, http.StatusUnauthorized, "invalid_credentials"); return
    }

    // В ПЗ10 здесь будет генерация JWT; пока просто ok
    writeJSON(w, http.StatusOK, authResp{
        Status: "ok",
        User:   map[string]any{"id": u.ID, "email": u.Email},
    })
}
```

### AutoMigrate (internal\repo\user_repo.go)

``` bash
func (r *UserRepo) AutoMigrate() error {
    return r.db.AutoMigrate(&core.User{})
} 
```
### Вызов AutoMigrate в main.go (internal\repo\user_repo.go)
``` bash
func main() {
    cfg := config.Load()
    db, err := repo.Open(cfg.DB_DSN)
    if err != nil { log.Fatal("db connect:", err) }

    if err := db.Exec("SET timezone TO 'UTC'").Error; err != nil { /* необязательно */ }

    users := repo.NewUserRepo(db)
    if err := users.AutoMigrate(); err != nil { log.Fatal("migrate:", err) }

    auth := &handlers.AuthHandler{Users: users, BcryptCost: cfg.BcryptCost}

    r := chi.NewRouter()
    r.Post("/auth/register", auth.Register)
    r.Post("/auth/login", auth.Login)

    log.Println("listening on", cfg.Addr)
    log.Fatal(http.ListenAndServe(cfg.Addr, r))
}
```

### Применение AutoMigrate позволяет создать в случае необходимости таблицу структуры User (internal\core\user.go)

``` bash
type User struct {
    ID           int64     `gorm:"primaryKey" json:"id"`
    Email        string    `gorm:"uniqueIndex;size:255;not null" json:"email"`
    PasswordHash string    `gorm:"size:255;not null" json:"-"`
    CreatedAt    time.Time `json:"createdAt"`
    UpdatedAt    time.Time `json:"updatedAt"`
}

```
### Запуск

<img width="1385" height="89" alt="image" src="https://github.com/user-attachments/assets/5a5ee2bb-5632-44b9-a4ed-36ac7e3eebbe" />

BCRYPT_COST по умолчанию стоит 12
APP_ADRR по умолчанию стоит ":8080"

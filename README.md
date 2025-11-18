# ЭФМО-01-25 Буров М.А. ПР9

# Описание проекта
Реализация регистрации и входа пользователей. Хэширование паролей с bcrypt.

# Требования к проекту
* Go 1.25+
* Postgres
* Git

# Версия Go
<img width="317" height="55" alt="image" src="https://github.com/user-attachments/assets/43f9087b-95b9-4c7d-86e9-746258c45c63" />

# Версия PostgreSQL
<img width="276" height="55" alt="image" src="https://github.com/user-attachments/assets/bca8a5ed-eb3b-4b1c-9eee-16fb8ec409e8" />

# Команды запуска и переменные окружения
```
setx DB_DSN "postgres://postgres:1234@localhost:5433/pz9?sslmode=disable"
```

# Цели:
-	Научиться безопасно хранить пароли (bcrypt), валидировать вход и обрабатывать ошибки.
-	Реализовать эндпоинты POST /auth/register и POST /auth/login.
-	Закрепить работу с БД (PostgreSQL + GORM или database/sql) и валидацией ввода.
-	Подготовить основу для JWT-аутентификации в следующем ПЗ (№10). 

# Структура проекта
Дерево структуры проекта: 
```
pz9-auth/
├── internal/
│   ├── http/
│   │   └── handlers/
│   │       └── auth.go
│   └── core/
│   │   └── user.go
│   ├── repo/
│   │   ├── postgres.go
│   │   └── user_repo.go
│   └── platform/
│       └── config/
│           └── config.go
├── cmd/
│   └── api/
│       └── main.go
└── go.mod
```

# Скриншоты

Успешная регистрация:


Повторная попытка:


Вход с верными данными:


Вход с неверными данными:


# Фрагменты кода

Оработчики Register, Login:
```
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

bcrypt.GenerateFromPassword и bcrypt.CompareHashAndPassword:
```
// bcrypt hash
hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), h.BcryptCost)
if err != nil {
    writeErr(w, http.StatusInternalServerError, "hash_failed"); return
}

u, err := h.Users.ByEmail(context.Background(), in.Email)
if err != nil {
    // не раскрываем, что именно не так
    writeErr(w, http.StatusUnauthorized, "invalid_credentials"); return
}

if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
    writeErr(w, http.StatusUnauthorized, "invalid_credentials"); return
}
```

SQL и миграции:
```
if err := users.AutoMigrate(); err != nil {
    log.Fatal("migrate:", err)
}
```

# Краткие выводы



# Ответы на контрольные вопросы

1.	В чём разница между хранением пароля и хранением его хэша? Зачем соль? Почему bcrypt, а не SHA-256? 


2.	Что произойдёт при снижении/повышении cost у bcrypt? Как подобрать значение? 


3.	Какие статусы и ответы должны возвращать POST /auth/register и POST /auth/login в типичных сценариях?


4.	Какие риски несут подробные сообщения об ошибках при логине?


5.	Почему в этом ПЗ не выдаём токен, и что изменится в ПЗ10 (JWT)? 

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
$env:DB_DSN="postgres://user:password@localhost:5432/pz9?sslmode=disable"
$env:BCRYPT_COST="12"
$env:APP_ADDR=":8080"

go run cmd/api/main.go
```
DB_DSN — строка подключения к PostgreSQL, BCRYPT_COST — параметр сложности хэширования (обычно 10–14), APP_ADDR — адрес и порт сервера.

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

<img width="1375" height="676" alt="image" src="https://github.com/user-attachments/assets/a44cc2a8-5119-405a-a018-146b9831ad0f" />

Повторная попытка:

<img width="1371" height="579" alt="image" src="https://github.com/user-attachments/assets/fc17dd8c-8cc8-435c-aac7-bd95d1668068" />

Вход с верными данными:

<img width="1370" height="700" alt="image" src="https://github.com/user-attachments/assets/a3e7bcca-8bbc-4935-b636-4cf842ba139e" />

Вход с неверными данными:

<img width="1378" height="584" alt="image" src="https://github.com/user-attachments/assets/4e88f895-3426-47fb-ac1f-51db6485d565" />

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

Почему нельзя хранить пароли в открытом виде: если база данных протечёт, злоумышленник получит доступ ко всем аккаунтам сразу, особенно если пользователи переиспользуют пароли на других сервисах. Компания будет дискредитирована, пользователи потеряют доверие.

Почему bcrypt: он медленный специально — проверка одного пароля занимает ~100–200 мс (в зависимости от cost), что затрудняет перебор даже одного пароля. SHA-256 — быстрый, его можно проверять миллионы раз в секунду на GPU. bcrypt также встраивает соль автоматически, защищая от радужных таблиц.

# Ответы на контрольные вопросы

1.	В чём разница между хранением пароля и хранением его хэша? Зачем соль? Почему bcrypt, а не SHA-256? 

Если хранить пароль в открытом виде, при утечке все аккаунты скомпрометированы. Хэш — это одностороннее преобразование; получить обратно пароль невозможно. При логине система хэширует введённый пароль и сравнивает с хранящимся хэшем.

Соль — это случайная строка, добавляемая к паролю перед хэшированием. Без соли два одинаковых пароля дают одинаковые хэши, и злоумышленник может подготовить таблицу хэшей популярных паролей (радужная таблица). С солью каждый пароль хэшируется уникально, даже если он простой.

SHA-256 — это быстрый алгоритм, который может проверяться миллионы раз в секунду, позволяя перебирать пароли. bcrypt — это медленный, итеративный алгоритм, где каждая проверка занимает сотни миллисекунд, делая перебор экономически нецелесообразным. bcrypt также встраивает соль в результат автоматически.

2.	Что произойдёт при снижении/повышении cost у bcrypt? Как подобрать значение? 

Cost — это логарифм числа итераций алгоритма. Cost=10 означает 2^10=1024 итерации, cost=12 — 2^12=4096 итераций. Каждое увеличение на 1 примерно удваивает время хэширования.

При снижении cost (например, с 12 на 8) хэширование ускоряется, но становится проще перебирать пароли. При повышении cost (с 12 на 14) хэширование замедляется, регистрация и логин будут долгими.

Подбирать нужно экспериментально: засеките время bcrypt.GenerateFromPassword на целевой машине. Должно быть 100–200 мс — достаточно медленно для защиты, но не мучительно для пользователя. Для локальной машины обычно cost=12 подходит. Для production сервера может быть 13–14.

3.	Какие статусы и ответы должны возвращать POST /auth/register и POST /auth/login в типичных сценариях?

POST /auth/register:

- 201 Created — успешная регистрация, возвращаем {"status":"ok","user":{"id":1,"email":"user@example.com"}}
- 400 Bad Request — невалидный email или короткий пароль (< 8 символов)
- 409 Conflict — email уже зарегистрирован, {"error":"email_taken"}
- 500 Internal Server Error — ошибка БД

POST /auth/login:

- 200 OK — успешный вход, возвращаем {"status":"ok","user":{"id":1,"email":"user@example.com"}}
- 400 Bad Request — пустой email или пароль
- 401 Unauthorized — неверный email или пароль (одно сообщение для обоих случаев!)
- 500 Internal Server Error — ошибка БД

4.	Какие риски несут подробные сообщения об ошибках при логине?

Если вернуть «Email не найден» при входе с неверным email, злоумышленник может перебирать email-адреса и узнать, какие пользователи зарегистрированы в системе. Если вернуть «Пароль неверный» после нахождения email, можно обнаружить существование конкретного аккаунта и сосредоточиться на переборе его пароля. Правильно — всегда возвращать одно сообщение: «Неверный логин или пароль», не раскрывая, что именно ошибочно.

5.	Почему в этом ПЗ не выдаём токен, и что изменится в ПЗ10 (JWT)? 

В этом ПЗ мы реализуем только аутентификацию (подтверждение личности — проверка email+пароля). После успешного логина приложение просто возвращает статус 200 OK.

В ПЗ 10 вместо 200 OK будет выдан JWT-токен (JSON Web Token) — подписанная строка, которая кодирует идентификатор пользователя.

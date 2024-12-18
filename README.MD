# Part Of The Token Based Authentication 🔐

![screen](https://github.com/pequod44/go-jwt/blob/dev/Media/access_refresh_tokens.gif)

## Описание
Этот проект представляет собой серверную часть системы аутентификации, использующую Access и Refresh токены. Реализация включает безопасное управление токенами с использованием SHA-512 для хэширования и проверку IP-адреса клиента.

## Функциональность
- **Генерация токенов**:
  - Access токен (действует 15 минут).
  - Refresh токен (действует 24 часа).
- **Валидация токенов**:
  - Проверка подписи и срока действия.
  - Сравнение хэша Refresh токена из базы данных.
- **Обновление токенов**:
  - Генерация новой пары Access и Refresh токенов.
  - Обновление хэша Refresh токена в базе данных.
- **Проверка IP-адреса**:
  - Отправка уведомления при изменении IP-адреса пользователя.

## Используемые технологии
- **Язык программирования**: Go
- **Фреймворк**: Gin
- **ORM**: GORM
- **База данных**: PostgreSQL
- **Токены**: JWT (JSON Web Tokens)

## Установка и запуск
1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/pequod44.git/go-jwt
   cd go-jwt
2. Установите зависимости:
   ```bash
   go mod tidy
3. Настройте переменные окружения в файле .env:<br>
    PORT=3000<br>
    dsn := "host=localhost user=gorm password=gorm dbname=gorm port=9920 sslmode=disable<br>
    KEY=your_secret_key
4. Запустите сервер:
   ```bash
   go run main.go

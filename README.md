# fast-api_test
Эксперименты с FastApi по одному из заданий<br>
запуск проекта <br>
python3 -m venv venv && . venv/bin/activate && python -m pip install --upgrade pip && python -m pip install -r requirements.txt && cd myproject && uvicorn main:app --reload<br>
документация http://127.0.0.1:8000/docs

Авторизация и аутентификация пользователей: Пользователи могут регистрироваться в системе, чтобы создавать свои аккаунты. Для входа в систему они используют свои учетные данные. После успешной аутентификации пользователи получают токен доступа, который используется для аутентификации при выполнении защищенных операций.

Управление постами: Пользователи могут создавать новые посты, редактировать уже существующие, а также удалять их. Каждый пост содержит заголовок, содержимое и информацию об авторе. Пользователи имеют возможность ставить лайки и снимать их с уже опубликованных постов.

Удобный интерфейс и безопасность: Приложение обеспечивает защищенный интерфейс, где данные пользователей и посты хранятся в безопасной базе данных. Аутентификация осуществляется с использованием JWT-токенов, что обеспечивает безопасную передачу данных между клиентом и сервером.

Простота использования и надежность: Приложение разработано с упором на простоту использования и надежность. Зарегистрированные пользователи могут легко создавать, изменять и удалять свои посты, а также оценивать публикации других пользователей.

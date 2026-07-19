Cloudflare Worker для защиты форм сайта «Ипотека-Просто»

Адрес Worker:
https://form-proxy.gudtsova1055.workers.dev/

В Cloudflare Workers должны быть настроены переменные:
1. TURNSTILE_SECRET_KEY — Secret, секретный ключ Turnstile.
2. MAKE_WEBHOOK_URL — URL вебхука Make. Рекомендуемый тип: Secret.
3. ALLOWED_ORIGIN — https://ipoteka-prosto.ru (код Worker также разрешает www).

Файл worker.js уже опубликован в Worker form-proxy. Не размещайте Secret Key и Make webhook в GitHub.

export default {
  async fetch(request, env) {
    const allowedOrigins = new Set([
      'https://ipoteka-prosto.ru',
      'https://www.ipoteka-prosto.ru'
    ]);
    const origin = request.headers.get('Origin') || '';
    const corsOrigin = allowedOrigins.has(origin) ? origin : 'https://ipoteka-prosto.ru';
    const corsHeaders = {
      'Access-Control-Allow-Origin': corsOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    };

    if (request.method === 'OPTIONS') {
      if (!allowedOrigins.has(origin)) return new Response(null, { status: 403, headers: corsHeaders });
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== 'POST') {
      return json({ success: false, message: 'Method not allowed' }, 405, corsHeaders);
    }
    if (!allowedOrigins.has(origin)) {
      return json({ success: false, message: 'Недопустимый источник запроса.' }, 403, corsHeaders);
    }
    if (!env.TURNSTILE_SECRET_KEY || !env.MAKE_WEBHOOK_URL) {
      return json({ success: false, message: 'Worker не настроен: отсутствуют секреты.' }, 500, corsHeaders);
    }

    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.toLowerCase().includes('application/json')) {
      return json({ success: false, message: 'Ожидается JSON.' }, 415, corsHeaders);
    }

    const length = Number(request.headers.get('Content-Length') || 0);
    if (length > 50000) {
      return json({ success: false, message: 'Слишком большой запрос.' }, 413, corsHeaders);
    }

    let payload;
    try { payload = await request.json(); }
    catch (_) { return json({ success: false, message: 'Некорректный JSON.' }, 400, corsHeaders); }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return json({ success: false, message: 'Некорректные данные формы.' }, 400, corsHeaders);
    }

    // Honeypot: поле website должно оставаться пустым.
    if (payload.website) {
      return json({ success: true }, 200, corsHeaders);
    }

    const token = String(payload.turnstile_token || '').trim();
    if (!token) {
      return json({ success: false, message: 'Не пройдена проверка безопасности.' }, 400, corsHeaders);
    }

    const ip = request.headers.get('CF-Connecting-IP') || '';
    const verifyBody = new URLSearchParams({
      secret: env.TURNSTILE_SECRET_KEY,
      response: token,
      remoteip: ip
    });

    let verification;
    try {
      const verifyResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: verifyBody
      });
      verification = await verifyResponse.json();
    } catch (_) {
      return json({ success: false, message: 'Сервис проверки временно недоступен.' }, 502, corsHeaders);
    }

    const validHostnames = new Set(['ipoteka-prosto.ru', 'www.ipoteka-prosto.ru']);
    if (!verification.success || !validHostnames.has(verification.hostname) || verification.action !== 'form_submit') {
      return json({ success: false, message: 'Проверка безопасности не пройдена.' }, 403, corsHeaders);
    }

    delete payload.turnstile_token;
    delete payload.website;
    payload.security = 'Cloudflare Turnstile: verified';
    payload.client_country = request.cf?.country || '';

    let makeResponse;
    try {
      makeResponse = await fetch(env.MAKE_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (_) {
      return json({ success: false, message: 'Не удалось передать заявку.' }, 502, corsHeaders);
    }

    if (!makeResponse.ok) {
      return json({ success: false, message: 'Сервис заявок временно недоступен.' }, 502, corsHeaders);
    }

    return json({ success: true }, 200, corsHeaders);
  }
};

function json(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' }
  });
}

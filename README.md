# UPI Gateway (Python/Flask) - Render free + Neon Postgres
1. Neon.tech: create free Postgres project, copy the connection string (DATABASE_URL).
2. Push this folder to a GitHub repo.
3. Render.com > New > Blueprint (or Web Service) > pick repo. Set DATABASE_URL and BASE_URL (https://yourapp.onrender.com).
4. Open BASE_URL, register, then in dashboard save Gmail, App Password, FamPay sender email, UPI ID, webhook.
5. UptimeRobot (free): HTTP monitor, every 5 min, URL = BASE_URL/ping?t=PING_TOKEN (token from Render env vars).
## API (X-Api-Key header or Bearer)
POST /api/create-order {"amount":199,"redirect_url":"","webhook_url":"","customer_name":""}
GET /api/checkout-status?order_id=   (public)   GET /api/verify-order?order_id=   (key)
Webhook header X-FamGateway-Signature = HMAC-SHA256(raw body, api_key). Compare timing-safe.
## Notes
Unique paise offset per open order (199.00, 199.01...). Emails are alerts: status "detected" -> confirm manually unless auto_confirm is on.
Late/ambiguous emails are never auto-assigned. Do not change APP_KEY later (saved App Passwords would become unreadable).

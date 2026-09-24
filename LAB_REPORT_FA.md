# گزارش نهایی آزمایشگاه h3ntun 0.4.0

تاریخ: ۲۰۲۶-۰۹-۲۴

دامنه: فقط loopback محلی

```text
client → Iran agent → uplink relay → foreign agent → backend
client ← Iran agent ← downlink relay ← foreign agent ← backend
```

uplink و downlink مستقل‌اند. هر relay می‌تواند delay، jitter، drop، duplicate، reorder یا outage تزریق کند. downlink از `127.0.0.2` ارسال می‌شود تا کنترل source مشاهده‌شده نیز آزمایش شود.

## نتایج

| پروفایل | ارسال | دریافت | نتیجه |
|---|---:|---:|---|
| clean | 100 | 100 | بدون retransmission و retry exhaustion |
| impaired | 200 | 200 | ۴۷ drop رفت، ۲۲ drop برگشت، ۳۳ duplicate و ۶۸ retransmitted frame |
| outage | 10 | 0 | مسیر برگشت عمداً خاموش بود |
| recovery | 30 | 30 | پس از وصل مسیر، صف‌های قبلی نیز ACK شدند |
| stress | 1000 | 1000 | بدون افت یا retry exhaustion |
| fec | 1 | 1 | حذف یک fragment و بازسازی با parity، بدون retransmission |
| maximum | 5 | 5 | پیام ۶۰۰۰۰بایتی با fragmentation کامل |
| oversize | 1 | 0 | پیام ۶۰۰۰۱بایتی رد و شمارنده افزایش یافت |

در پروفایل impaired همهٔ پیام‌ها تحویل شدند. duplicate frameها توسط replay/dedup حذف شدند و پیام دوباره به backend یا client تحویل نشد. `auth_failures` و `source_mismatch_drops` در تمام پروفایل‌های عادی صفر بودند.

## موارد اثبات‌شده

- رمزنگاری end-to-end frameهای تونل؛
- ACK روی مسیر مخالف؛
- retransmission و backoff؛
- FEC تک‌پاریتی؛
- fragmentation و reassembly؛
- جلوگیری از duplicate delivery؛
- بازیابی بعد از outage؛
- محدودیت اندازه و صف؛
- کنترل source برگشت.

## خارج از دامنه loopback

این آزمایش ظرفیت یا دسترسی اینترنت عمومی، پذیرش source توسط اپراتور، systemd، route policy، iptables/nftables و MTU واقعی مسیر را اثبات نمی‌کند. این موارد باید روی endpointهای واقعی، مجاز و متعلق به اپراتور پروژه acceptance test شوند.

اعداد کامل در `LAB_REPORT.json` ذخیره شده‌اند.

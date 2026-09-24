# گزارش محیط آزمایش پیوند نامتقارن

تاریخ اجرا: ۲۰۲۶-۰۹-۲۳

دامنه: فقط loopback محلی

فرمان: `python scripts/lab_environment.py --profile all --output LAB_REPORT.json`

## معماری آزمایش

```text
کلاینت محلی
    │ UDP
    ▼
عامل ایران ──► relay رفت ──► عامل خارج ──► backend
    ▲                                      │
    └──── relay برگشت از 127.0.0.2 ◄───────┘
```

uplink و downlink دو relay مستقل‌اند و می‌توانند delay، jitter، drop، duplicate، reorder و outage متفاوت داشته باشند. همه آدرس‌ها loopback و قابل bind هستند؛ raw socket، مبدأ جعل‌شده یا شبکه عمومی استفاده نمی‌شود.

## نتایج آخرین اجرا

| پروفایل | ارسال | دریافت | افت | نتیجه مهم |
|---|---:|---:|---:|---|
| clean | 100 | 100 | 0% | میانگین RTT شبیه‌سازی‌شده 33.99 ms |
| impaired | 200 | 171 | 14.5% | ۲۰ drop در رفت، ۹ drop در برگشت و رد ۱۳ duplicate به‌عنوان replay |
| outage | 10 | 0 | 100% | downlink عمداً قطع بود |
| recovery | 30 | 30 | 0% | پس از وصل relay کاملاً بازیابی شد |
| stress | 1000 | 1000 | 0% | burst کامل بدون افت در میزبان آزمایش |
| maximum payload | 5 | 5 | 0% | payload برابر ۶۰۰۰۰ بایت پذیرفته شد |
| oversize | 1 | 0 | 100% | payload برابر ۶۰۰۰۱ بایت رد و شمارنده افزایش یافت |

در پروفایل impaired افت عمدی است. این نتیجه روشن می‌کند که transport در نسخه فعلی reliability اضافه نمی‌کند: duplicate با replay protection حذف می‌شود، اما packet حذف‌شده retransmit نمی‌شود.

## چیزی که این آزمایش اثبات می‌کند

- جدایی منطقی مسیر رفت و برگشت؛
- احراز HMAC و replay protection؛
- بررسی source مشاهده‌شده در downlink؛
- تحویل صحیح درخواست به backend و پاسخ به کلاینت؛
- تحمل reorder در محدوده replay window؛
- بازیابی پس از بازگشت مسیر؛
- رفتار پایدار در burst محلی؛
- اجرای درست محدودیت اندازه payload.

## چیزی که اثبات نمی‌کند

- دسترسی یا ظرفیت هیچ مسیر اینترنتی واقعی؛
- پذیرش SNAT یا source انتخابی توسط دیتاسنتر یا اپراتور؛
- عملکرد systemd، route policy، iptables/nftables یا MTU در Linux؛
- امکان عبور از فایروال یا محدودیت شبکه عمومی؛
- امنیت محرمانگی payload؛ HMAC فقط اصالت و یکپارچگی می‌دهد.

جزئیات عددی کامل در `LAB_REPORT.json` قرار دارد.

# گزارش نهایی اصلاح محدودیت‌ها و تغییر نام

تاریخ: ۲۰۲۶-۰۹-۲۴

نسخه: `h3ntun 0.4.0` — wire protocol نسخه ۳

## نتیجه

- ۱۰۷ تست از ۱۰۷ تست موفق؛
- آزمایش clean برابر ۱۰۰/۱۰۰؛
- آزمایش impaired برابر ۲۰۰/۲۰۰ با drop، duplicate، jitter و reorder عمدی؛
- آزمایش stress برابر ۱۰۰۰/۱۰۰۰؛
- قطع downlink برابر ۰/۱۰ و پس از بازیابی ۳۰/۳۰؛
- بازیابی یک fragment حذف‌شده با FEC و بدون retransmission؛
- عبور پیام ۶۰۰۰۰بایتی و رد پیام ۶۰۰۰۱بایتی؛
- sandbox برابر ۱۰۰/۱۰۰ با رد source نادرست و ciphertext دستکاری‌شده.

## محدودیت‌هایی که اصلاح شدند

1. payload از حالت HMAC-only به رمزنگاری کامل `ChaCha20-Poly1305` منتقل شد.
2. پیام بزرگ به fragmentهای پیش‌فرض ۱۲۰۰بایتی تقسیم می‌شود و دیگر مستقیماً یک دیتاگرام بسیار بزرگ تونل تولید نمی‌کند.
3. یک fragment گمشده با parity FEC بازسازی می‌شود.
4. افت بیشتر با ACK و retransmission جبران می‌شود.
5. retryها backoff نمایی و congestion window از نوع AIMD دارند.
6. صف و reassembly table محدود هستند تا حافظه بدون سقف رشد نکند.
7. replay state به‌صورت اتمیک روی دیسک ذخیره می‌شود و پس از restart باقی می‌ماند.
8. state خراب یا متعلق به tunnel دیگر باعث fail-closed شدن startup می‌شود.
9. installer وابستگی رمزنگاری را در virtualenv مجزا نصب می‌کند.
10. package، command، service، user و مسیر نصب به `h3ntun` تغییر نام دادند.

## محدودیت‌هایی که نرم‌افزار نمی‌تواند حذف کند

- مسیر شبکه و source باید توسط کرنل، دیتاسنتر و اپراتور پذیرفته شود؛
- outage طولانی‌تر از بودجه queue/retry می‌تواند باعث انقضای پیام شود؛
- این برنامه UDP transport است، نه TUN/TAP و نه router عمومی؛
- نسخه فعلی transport socket روی IPv4 است؛
- acceptance نهایی systemd، route، firewall و MTU باید روی دو سرور واقعی و مجاز انجام شود.

هیچ IP شخص ثالث یا ارسال زنده با source جعل‌شده در تست‌ها استفاده نشده است.

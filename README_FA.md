# پیوند نامتقارن UDP — نمونه‌ی پژوهشی مستقل

این پوشه یک پروژه‌ی مستقل است و هیچ فایل، سرویس یا تنظیمی از پروژه‌های دیگر را تغییر نمی‌دهد. هدف آن حمل دیتاگرام‌های یک سرویس محلی بین دو سرور است، در حالی که مسیر رفت و برگشت می‌توانند متفاوت باشند.

## نتیجه‌ی فنی کوتاه

معماری نامتقارن شدنی است، اما فقط وقتی هر دو مسیر واقعاً قابل مسیریابی باشند:

```text
سرویس محلی ایران
      │ UDP
      ▼
عامل ایران ─── DATA_UP / مسیر خروجی خریداری‌شده ───► عامل خارج
      ▲                                                   │
      │                                                   ▼ UDP
      └──── DATA_DOWN / مسیر برگشت مجاز ───────── سرویس محلی خارج
```

عامل ایران بسته‌ی داخلی را با شناسه‌ی تونل، شماره‌ی ترتیبی، زمان و HMAC می‌فرستد. عامل خارج آن را احراز می‌کند و به peer محلی تحویل می‌دهد. پاسخ peer دوباره قاب‌بندی شده و از مسیر برگشت به عامل ایران می‌رسد. عامل ایران مبدأ مشاهده‌شده، HMAC و replay را کنترل می‌کند و سپس پاسخ را به برنامه‌ی محلی برمی‌گرداند.

نسخه‌ی برنامه `0.3.0` و نسخه‌ی wire protocol برابر ۲ است. قاب نسخه ۲ یک `session_id` تصادفی و احراز‌شده دارد تا restart یک‌طرفه با sequence پایین‌تر باعث قفل‌شدن replay window نشود. این wire format با نسخه‌ی ۱ سازگار نیست؛ هر دو سرور باید هم‌زمان به‌روزرسانی شوند.

این برنامه مسیر بسته را در اینترنت ایجاد نمی‌کند. اگر مسیر مستقیم خارج به ایران مسدود باشد، تنظیم یک مبدأ دلخواه به‌تنهایی آن را قابل‌دسترسی نمی‌کند. مبدأ عملیاتی باید واقعاً روی سرور خارج تخصیص یافته و تا مقصد route شده باشد؛ در غیر این صورت bind سیستم‌عامل یا فیلترهای ضد جعل آن را رد می‌کنند و پاسخ برگشتی هم وجود ندارد.

## چرا دستور SNAT به‌تنهایی تونل نیست

الگوی زیر فقط یک بازنویسی مبدأ است:

```text
iptables -t nat -A POSTROUTING -d iran_ip -j SNAT --to-source spoof_ip
```

برای کارکرد قانونی، `spoof_ip` باید آدرسی باشد که مالک/اپراتور آن را به همان میزبان تخصیص داده و مسیر برگشتش را فراهم کرده است. این دستور:

- مسیر جدید ایجاد نمی‌کند؛
- تضمین نمی‌کند فایروال مقصد بسته را بپذیرد؛
- دریافت پاسخ برای مبدأ جعلی را ممکن نمی‌کند؛
- جای state، احراز اصالت و replay protection را نمی‌گیرد؛
- ممکن است در مبدأ یا شبکه‌ی بالادست با فیلتر ضد جعل حذف شود.

به همین دلیل runtime این پروژه raw spoofing زنده ندارد. `packet-selftest` فقط ساختار checksum یک بسته را در حافظه آزمایش می‌کند و چیزی روی شبکه نمی‌فرستد.

## نسبت آپلود و دانلود

این معماری می‌تواند برای workloadهایی که پاسخ آن‌ها از درخواست بزرگ‌تر است، مصرف مسیر رفت را نسبت به مسیر برگشت کم کند؛ اما «۱ گیگ رفت = ۱۰ گیگ فروش» تضمین فنی نیست. ACK، keepalive، درخواست‌ها، retransmission و ترافیک کنترلی همچنان روی مسیر رفت مصرف دارند. نسبت واقعی فقط با شمارنده‌های `uplink_*` و `downlink_*` همین برنامه و حسابداری ارائه‌دهنده مشخص می‌شود.

## نیازمندی‌ها

- دو میزبان Linux با Python 3.10 یا جدیدتر و systemd؛
- یک مسیر UDP از ایران به `foreign_ip:uplink_port`؛
- یک مسیر UDP قانونی از خارج به `iran_ip:downlink_port`؛
- ساعت همگام روی دو سرور؛
- یک برنامه‌ی UDP محلی در هر سمت؛
- payload داخلی رمز‌شده، اگر محرمانگی لازم است. این لایه HMAC دارد ولی payload را رمز نمی‌کند.

این پروژه به پنل خاصی وابسته نیست و یک پنل به‌تنهایی جای transport نامتقارن را نمی‌گیرد.

## آماده‌سازی تنظیمات

روی یک سیستم امن، شناسه و secret بسازید:

```bash
python3 -m asym_link generate-secret --json
```

دو فایل نمونه را کپی کنید و `tunnel_id` و `shared_secret` یکسان را در هر دو قرار دهید:

```bash
cp config/iran.example.json iran.json
cp config/foreign.example.json foreign.json
```

مقادیر بیرونی فقط با placeholder آمده‌اند:

- `foreign_ip`: مقصد واقعی و مجاز مسیر رفت؛
- `iran_ip`: مقصد واقعی و مجاز مسیر برگشت؛
- `source_ip_assigned_to_server`: آدرسی که واقعاً روی میزبان خارج assign شده است؛ در صورت حذف یا `null`، کرنل مبدأ را انتخاب می‌کند؛
- `expected_downlink_source`: مبدأیی که سرور ایران باید واقعاً روی بسته‌ی برگشت مشاهده کند. برای غیرفعال کردن این allowlist مقدار را `null` کنید.
- `expected_inner_peer`: IP و port ثابت برنامه‌ی محلی ایران. اگر برنامه port ثابت دارد، تنظیم آن از تعویض peer توسط process محلی دیگر جلوگیری می‌کند؛ در حالت dynamic مقدار `null` بماند.

فایل نمونه عمداً تا قبل از جایگزینی placeholderها در `check` رد می‌شود.

## مسیریابی مسیر رفت

ارائه‌دهنده‌ی خروجی باید یک interface یا gateway مشخص بدهد. فقط endpoint خارج را از آن مسیر عبور دهید تا دسترسی مدیریتی سرور جابه‌جا نشود. الگوهای عمومی:

```text
ip route replace foreign_ip/32 dev outbound_interface
ip route replace foreign_ip/32 via outbound_gateway dev outbound_interface
```

یکی از دو الگو، مطابق نوع تحویل سرویس، استفاده می‌شود. نصب‌کننده عمداً route و firewall را تغییر نمی‌دهد تا اتصال مدیریتی سرور قطع نشود.

## پیش‌بررسی و نصب سرور ایران

کل پوشه را روی سرور ایران کپی کنید، سپس:

```bash
sudo bash scripts/preflight.sh /root/iran.json
sudo bash scripts/install-iran.sh /root/iran.json
```

`preflight` تنظیمات، DNS، انتخاب route، bind محلی و وضعیت ساعت را بررسی می‌کند ولی probe شبکه نمی‌فرستد.

## پیش‌بررسی و نصب سرور خارج

کل پوشه را روی سرور خارج کپی کنید، سپس:

```bash
sudo bash scripts/preflight.sh /root/foreign.json
sudo bash scripts/install-foreign.sh /root/foreign.json
```

اگر `downlink_source` تنظیم شده باشد، سرویس با UDP معمولی روی همان IP bind می‌کند. اگر IP روی میزبان assign نشده باشد نصب یا اجرای سرویس شکست می‌خورد؛ این رفتار عمدی است.

## اتصال برنامه‌های محلی

- برنامه‌ی محلی ایران باید دیتاگرام را به `inner_listen` بفرستد.
- عامل خارج دیتاگرام را از `inner_bridge_listen` به `inner_peer` می‌فرستد.
- پاسخ `inner_peer` از همان socket به عامل خارج برمی‌گردد.

برای تست پذیرش، ابتدا روی سرور خارج یک echo peer موقت اجرا کنید:

```bash
cd /opt/hy-asym-link/app
sudo -u hy-asym-link PYTHONPATH=. python3 -m asym_link echo --listen 127.0.0.1:51820
```

سپس روی ایران probe بفرستید:

```bash
cd /opt/hy-asym-link/app
sudo -u hy-asym-link PYTHONPATH=. python3 -m asym_link probe --target 127.0.0.1:5000 --count 10
```

پس از پایان تست، echo را با Ctrl+C متوقف کنید و peer واقعی را اجرا کنید.

## راستی‌آزمایی عملیاتی

روی هر دو سرور:

```bash
sudo bash /opt/hy-asym-link/scripts/verify.sh
sudo systemctl status hy-asym-link --no-pager
sudo journalctl -u hy-asym-link -n 100 --no-pager
```

موفقیت کامل یعنی:

- `healthy=true`؛
- در ایران `downlink_rx_packets` و `uplink_tx_packets` بزرگ‌تر از صفر باشند؛
- در خارج `uplink_rx_packets` و `downlink_tx_packets` بزرگ‌تر از صفر باشند؛
- `auth_failures`, `replay_drops` و `source_mismatch_drops` صفر بمانند؛
- `last_downlink_source` دقیقاً با `expected_downlink_source` یکسان باشد؛
- probe با payload یکسان برگردد.

دیدن یک بسته با مبدأ خاص فقط «مبدأ مشاهده‌شده» را اثبات می‌کند، نه مالکیت آن IP یا عبور پایدار در شرایط بحران.

## اسکن امن sourceهای اختصاص‌یافته

ابزار `scripts/spoof_scanner.py` با وجود نام قدیمی فایل، raw spoof انجام نمی‌دهد. هر candidate باید واقعاً روی فرستنده assign شده و قابل bind باشد. probeها با secret تونل HMAC می‌شوند.

روی سمت دریافت، برای یک بازه‌ی محدود:

```bash
python3 scripts/spoof_scanner.py receiver \
  --listen 0.0.0.0:probe_port \
  --config /etc/hy-asym-link/config.json \
  --duration 30 \
  --update-config
```

روی سمت ارسال:

```bash
python3 scripts/spoof_scanner.py scanner \
  --target iran_ip:probe_port \
  --config /etc/hy-asym-link/config.json \
  --candidates-file scripts/candidates.example.txt \
  --probes 10
```

فایل candidate باید فقط IPهای متعلق یا اختصاص‌یافته به همان سرور را داشته باشد. IP غیرمحلی با وضعیت `not-local` رد می‌شود. تغییر خودکار config تنها با حداقل سه probe معتبر انجام و نسخه‌ی `.bak` نگهداری می‌شود.

برای source NAT از یک IP واقعاً assign‌شده:

```text
sudo bash scripts/setup-foreign-snat.sh --apply iran_ip assigned_source_ip downlink_port source_port
sudo bash scripts/setup-foreign-snat.sh --remove iran_ip assigned_source_ip downlink_port source_port
```

برای route و `rp_filter` محدود به interface، راهنمای خود اسکریپت را ببینید:

```bash
sudo bash scripts/setup-iran-network.sh --help
```

## firewall با placeholder

فقط UDPهای موردنیاز را باز کنید و health را روی loopback نگه دارید. الگوی منطقی:

```text
سمت خارج: allow UDP from authorized_uplink_source to uplink_port
سمت ایران: allow UDP from assigned_return_source to downlink_port
هر دو سمت: deny سایر ورودی‌های همان پورت
```

فرمان اجرایی firewall عمداً تولید نشده است، چون backend و ترتیب ruleهای هر سرور متفاوت است و یک rule اشتباه می‌تواند دسترسی مدیریتی را قطع کند.

## توقف، rollback و حذف

```bash
sudo systemctl stop hy-asym-link
sudo systemctl disable hy-asym-link
sudo bash /opt/hy-asym-link/scripts/uninstall.sh
```

حذف عادی config و metrics را نگه می‌دارد. حذف کامل و برگشت‌ناپذیر:

```bash
sudo bash /opt/hy-asym-link/scripts/uninstall.sh --purge
```

## محدودیت‌ها

- فقط UDP و یک peer فعال در سمت ایران؛
- حداکثر payload قاب ۶۰٬۰۰۰ بایت، اما برای جلوگیری از fragmentation بهتر است payload داخلی حدود ۱۲۰۰ بایت یا کمتر باشد؛
- بدون رمزنگاری payload؛ فقط احراز اصالت HMAC؛
- بدون FEC، congestion control یا تضمین تحویل؛
- raw source spoofing زنده ندارد؛
- مسیر blocked را به‌تنهایی قابل‌عبور نمی‌کند.

## اجرای تست‌های خود پروژه

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q asym_link tests scripts
python3 -m asym_link packet-selftest
python3 scripts/lab_environment.py --profile all --output LAB_REPORT.json
```

تست integration یک رفت‌وبرگشت واقعی UDP روی loopback انجام می‌دهد و هر دو agent، peer شبیه‌سازی‌شده، HMAC، replay window و کنترل مبدأ را درگیر می‌کند.

آزمایشگاه `lab_environment.py` دو relay مستقل برای uplink و downlink می‌سازد و پنج پروفایل دارد:

- `clean`: تأخیر جداگانه و بدون loss؛
- `impaired`: delay، jitter، loss، reorder و duplicate؛
- `outage`: قطع کامل downlink و بازیابی؛
- `stress`: burst هزار دیتاگرامی؛
- `boundary`: payload برابر ۶۰٬۰۰۰ و payload بیش‌ازحد.

همه‌ی relayها روی loopback هستند و این آزمایشگاه مسیر عمومی، iptables یا جعل مبدأ را آزمایش نمی‌کند.

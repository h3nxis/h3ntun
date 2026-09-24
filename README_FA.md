# h3ntun — تونل UDP رمز‌شده با مسیر رفت‌وبرگشت نامتقارن

`h3ntun` برای حالتی طراحی شده که مسیر مجاز رفت و برگشت یکسان نیست. برنامه دیتاگرام UDP محلی را دریافت می‌کند، آن را رمز می‌کند، به fragmentهای کوچک تقسیم می‌کند و از مسیر تعیین‌شده می‌فرستد. سمت مقابل fragmentها را بازسازی و به برنامه UDP محلی تحویل می‌دهد.

## قابلیت‌های نسخه ۰.۴.۰

- رمزنگاری و احراز اصالت `ChaCha20-Poly1305`؛
- مشتق‌سازی کلید مستقل تونل با `HKDF-SHA256`؛
- wire protocol نسخه ۳ با session تصادفی و nonce یکتا؛
- fragmentation پیش‌فرض ۱۲۰۰ بایت و بازسازی پیام تا ۶۰۰۰۰ بایت؛
- FEC تک‌پاریتی برای بازیابی یک fragment گمشده بدون انتظار برای retransmission؛
- ACK دوطرفه، retransmission با backoff نمایی و پنجره congestion از نوع AIMD؛
- صف محدود برای جلوگیری از مصرف نامحدود حافظه؛
- replay state پایدار با ذخیرهٔ اتمیک پیش از تحویل فریم؛
- کنترل مبدأ بیرونی و peer داخلی؛
- آزمایشگاه loopback برای delay، jitter، loss، duplicate، reorder، outage، recovery، FEC و stress.

نسخه ۳ پروتکل با نسخه‌های قدیمی سازگار نیست و هر دو سرور باید هم‌زمان ارتقا پیدا کنند.

## تغییرات توسعه‌ای منتشرنشده

در شاخهٔ توسعه، replay check در حافظه انجام می‌شود و checkpoint به writer مستقل
با یک جایگاه snapshot منتقل شده است. پیامد crash سخت در بخش تنظیمات توضیح داده شده است.

## معماری

```text
برنامه UDP محلی ایران
        │
        ▼
عامل ایران ── DATA و ACK رمز‌شده روی مسیر رفت ──► عامل خارج
        ▲                                            │
        │                                            ▼
        └──── DATA و ACK رمز‌شده روی مسیر برگشت ─ برنامه UDP خارج
```

ACK درخواست رفت روی مسیر برگشت ارسال می‌شود. ACK پاسخ برگشت نیز روی مسیر رفت حرکت می‌کند. بنابراین قابلیت reliability بدون یکی‌کردن routeها کار می‌کند.

## مرز امنیتی شبکه

برنامه فقط از UDP socket معمولی و sourceای استفاده می‌کند که کرنل اجازه bind آن را بدهد. `downlink_source` باید واقعاً روی همان سرور assign شده باشد یا مقدار آن `null` باشد تا کرنل source را انتخاب کند. برنامه مبدأ غیرمحلی جعل نمی‌کند.

وجود نرم‌افزار به‌تنهایی route اینترنتی ایجاد نمی‌کند. مسیر رفت و برگشت، فایروال و سیاست اپراتور باید واقعاً ترافیک را بپذیرند.

## نصب سریع

نیازمندی‌ها:

- Linux و Python 3.10 یا جدیدتر؛
- systemd و ماژول `venv` پایتون؛
- مسیر UDP مجاز از ایران به سرور خارج؛
- مسیر UDP مجاز از خارج به ایران؛
- ساعت همگام روی دو سرور.

ابتدا secret بسازید:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
h3ntun generate-secret --json
```

نمونه تنظیمات را کپی کنید:

```bash
cp config/iran.example.json iran.json
cp config/foreign.example.json foreign.json
```

`tunnel_id` و `shared_secret` در دو سمت باید یکسان باشند. تمام placeholderها را تغییر دهید.

نصب سمت ایران:

```bash
sudo bash scripts/install-iran.sh ./iran.json
```

نصب سمت خارج:

```bash
sudo bash scripts/install-foreign.sh ./foreign.json
```

installer یک virtualenv در `/opt/h3ntun/venv` می‌سازد، وابستگی رمزنگاری را نصب می‌کند و سرویس را با کاربر محدود `h3ntun` اجرا می‌کند.

## تنظیمات reliability و fragmentation

- `fragment_payload_bytes`: بین ۲۵۶ تا ۱۳۹۱؛ مقدار پیشنهادی ۱۲۰۰. سقف ۱۳۹۱ با
  سربار فریم رمز‌شده و IPv4/UDP دقیقاً داخل MTU برابر ۱۵۰۰ جا می‌شود؛
- `fec_enabled`: برای پیام چندfragmentی یک parity fragment اضافه می‌کند؛
- `reliable`: ACK و retransmission را فعال می‌کند؛
- `retransmit_timeout_seconds`: timeout اولیه؛ retryهای بعدی backoff نمایی دارند؛
- `max_retries`: تعداد retry پس از ارسال اولیه؛
- `max_pending_messages`: سقف مجموع پیام‌های queued و in-flight؛
- `reassembly_timeout_seconds`: زمان نگهداری پیام ناقص؛
- `replay_state_file`: فایل state پایدار؛ برای هر agent باید جدا باشد.
- `replay_checkpoint_interval_seconds`: فاصلهٔ عادی checkpoint؛ پیش‌فرض ۰٫۰۵ ثانیه؛
- `replay_checkpoint_batch_frames`: انجام زودتر checkpoint پس از این تعداد فریم؛ پیش‌فرض ۱۲۸.
  writer فقط یک snapshot منتظر را نگه می‌دارد و snapshotهای تازه جای قبلی را می‌گیرند.

پردازش فریم منتظر نوشتن دیسک نمی‌ماند. پس از crash سخت، فریم‌هایی که بعد از آخرین
checkpoint پایدار پذیرفته شده‌اند ممکن است دوباره پذیرفته شوند. خاموشی عادی آخرین
state را تا سقف پنج ثانیه flush می‌کند. برای پایش از `replay_checkpoint_lag_frames`،
`replay_checkpoint_lag_ms`، `replay_write_latency_ms` و `replay_persistence_errors`
در status/metrics استفاده کنید.

اگر مسیر برای مدت بیشتری از بودجه retry قطع بماند، پیام منقضی می‌شود و شمارنده `retry_exhausted` افزایش می‌یابد. مقدار timeout و retry را متناسب با نوع لینک تنظیم کنید.

## تنظیمات کنترل مبدأ

- `expected_downlink_source`: IP مشاهده‌شده و مجاز برای مسیر برگشت؛
- `downlink_source`: IP واقعاً assign‌شده به سرور خارج؛
- `expected_inner_peer`: IP و port ثابت برنامه محلی ایران؛
- `inner_peer`: peer ثابت برنامه محلی سمت خارج.

اسکریپت `scripts/source_scanner.py` فقط sourceهای local و قابل bind را بررسی می‌کند. raw socket ندارد و نمی‌تواند source غیرمحلی ارسال کند.

## بررسی سرویس

```bash
sudo systemctl status h3ntun --no-pager
sudo journalctl -u h3ntun -n 100 --no-pager
sudo bash /opt/h3ntun/scripts/verify.sh
```

health endpoint به‌صورت پیش‌فرض فقط روی loopback است. شمارنده‌های زیر باید بررسی شوند:

- `auth_failures` و `source_mismatch_drops`؛
- `queue_drops` و `retry_exhausted`؛
- `retransmitted_frames` و `fec_recoveries`؛
- `queued_messages`، `inflight_messages` و `congestion_window`؛
- `last_ack_rtt_ms` و زمان آخرین uplink/downlink.

## محیط آزمایش

```bash
python -m compileall -q h3ntun tests scripts
python -m unittest discover -s tests -q
python scripts/lab_environment.py --profile all --output LAB_REPORT.json
python scripts/test_asym_sandbox.py
```

پروفایل‌های lab:

- `clean`: مسیر سالم؛
- `impaired`: loss، delay، jitter، reorder و duplicate؛
- `outage`: قطع و بازیابی مسیر برگشت؛
- `stress`: هزار پیام؛
- `fec`: حذف دقیق یک fragment و بازسازی با parity؛
- `boundary`: پیام ۶۰۰۰۰بایتی و رد پیام ۶۰۰۰۱بایتی.

## ارتقا از نسخه ۰.۳

1. سرویس هر دو سمت را متوقف کنید.
2. هر دو سمت را به ۰.۴ ارتقا دهید.
3. تنظیمات جدید reliability و `replay_state_file` را اضافه کنید.
4. سرویس‌ها را شروع و `verify.sh` را اجرا کنید.

پروتکل نسخه ۲ و ۳ با هم ارتباط برقرار نمی‌کنند.

## محدودیت‌های بنیادی باقی‌مانده

- نرم‌افزار نمی‌تواند route مسدود یا source ردشده توسط اپراتور را قابل‌دسترسی کند؛
- reliability محدود به queue و retry تنظیم‌شده است؛
- این برنامه دیتاگرام UDP حمل می‌کند و TUN/TAP یا router عمومی IP نیست؛
- نسخه فعلی socketهای حمل را روی IPv4 اجرا می‌کند؛
- آزمون loopback جای acceptance test روی دو میزبان واقعی و مجاز را نمی‌گیرد.

استفاده فقط روی سرورها، آدرس‌ها و مسیرهایی مجاز است که مالک آن هستید یا اجازه صریح بهره‌برداری از آن‌ها را دارید.

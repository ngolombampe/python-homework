#!/usr/bin/env python3
"""
01_nvd_basic.py — найпростіший запит до NVD API 2.0

ЩО ТАКЕ NVD?
NVD (National Vulnerability Database) — це база даних вразливостей, яку веде
американський інститут NIST. Кожна вразливість має унікальний номер (CVE ID),
опис, оцінку небезпеки (CVSS) і перелік уражених продуктів.

ЩО РОБИТЬ ЦЕЙ СКРИПТ:
  1. Надсилає один HTTP-запит до NVD і шукає вразливості за ключовим словом
  2. Дістає з відповіді CVE ID, статус, оцінку CVSS і короткий опис
  3. Виводить результат у консоль

ЗАПУСК:
    python 01_nvd_basic.py            # шукає "OpenSSH"
    python 01_nvd_basic.py nginx      # шукає "nginx"

ВАЖЛИВО (стан на 2026 рік):
З 15 квітня 2026 року NIST більше НЕ додає оцінку CVSS до кожної CVE.
Пріоритет мають CVE з каталогу CISA KEV та критичне ПЗ уряду США.
Решта отримує статус "Not Scheduled" і може ніколи не мати оцінки від NVD.
Тому не дивуйтеся, якщо у частини результатів score буде порожній —
це не помилка скрипта, це нова реальність. Що з цим робити — дивіться
скрипт 03_kev_epss.py.
"""

# ── Імпорти ───────────────────────────────────────────────────────────────────
# os     — потрібен, щоб прочитати API-ключ зі змінної середовища
# sys    — для аргументів командного рядка та коду виходу
# time   — для пауз між повторними спробами (rate limiting)
# requests — бібліотека для HTTP-запитів (встановлюється: pip install requests)
import os
import sys
import time
from dotenv import load_dotenv

import requests

# ── Константи ─────────────────────────────────────────────────────────────────
# Константи пишуть ВЕЛИКИМИ літерами. Це домовленість між програмістами:
# "це значення не змінюється під час роботи програми".
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# User-Agent — це "візитівка" нашої програми. Ввічливі клієнти вказують,
# хто саме стукає в API. Не вигадуйте, що ви браузер: пишіть чесно.
USER_AGENT = "CyberCourse-Lesson9/2.0 (educational script)"

# Скільки секунд чекати між запитами.
# NVD дозволяє: без ключа — 5 запитів на 30 секунд, з ключем — 50 на 30 секунд.
# 30 / 5 = 6 секунд без ключа; 30 / 50 = 0.6 секунди з ключем.
DELAY_WITHOUT_KEY = 6.0
DELAY_WITH_KEY = 0.6


def get_api_key() -> str | None:
    """
    Читає API-ключ NVD зі змінної середовища NVD_API_KEY.

    ЧОМУ САМЕ ТАК, А НЕ ПРОСТО ВПИСАТИ КЛЮЧ У КОД?
    Ключ, вписаний у код, рано чи пізно потрапить у Git, а з Git — у GitHub,
    а з GitHub — до всіх охочих. Це найпоширеніший спосіб "злити" секрет.
    Змінна середовища живе тільки у вашій системі і не комітиться.

    Як задати ключ (ключ безкоштовний: nvd.nist.gov/developers/request-an-api-key):
        macOS / Linux:   export NVD_API_KEY="ваш-ключ"
        Windows (PS):    $env:NVD_API_KEY = "ваш-ключ"

    Повертає:
        Рядок з ключем або None, якщо змінної немає.
    """
    # os.environ — це словник з усіма змінними середовища.
    # .get() повертає None, якщо ключа немає (на відміну від [], який впаде з помилкою).
    load_dotenv()
    return os.environ.get("NVD_API_KEY")


def build_headers() -> dict[str, str]:
    """
    Збирає заголовки HTTP-запиту.

    Заголовки — це "службові поля" запиту: хто питає, у якому форматі
    хоче відповідь, з яким ключем доступу.
    """
    headers = {"User-Agent": USER_AGENT}

    api_key = get_api_key()
    if api_key:
        # NVD очікує ключ саме у заголовку "apiKey" (не в URL!).
        # Секрети в URL — погана практика: вони потрапляють у логи серверів.
        headers["apiKey"] = api_key

    return headers


def search_nvd(keyword: str, limit: int = 5, retries: int = 3) -> dict:
    """
    Шукає вразливості у NVD за ключовим словом.

    Параметри:
        keyword: що шукаємо, наприклад "OpenSSH"
        limit:   скільки результатів повернути (1..2000)
        retries: скільки разів повторити спробу, якщо сервер відповів помилкою

    Повертає:
        Словник з відповіддю API (розпакований JSON).

    ЧОМУ ПОТРІБНІ ПОВТОРНІ СПРОБИ?
    NVD — безкоштовний сервіс під великим навантаженням. Він регулярно
    відповідає 503 (сервіс недоступний) або 429 (забагато запитів).
    Скрипт, який падає від першої ж 503, у реальній роботі непридатний.
    """
    params = {
        "keywordSearch": keyword,        # пошук за словом в описі CVE
        "resultsPerPage": str(limit),    # скільки записів на "сторінці"
    }
    headers = build_headers()

    # Пауза залежить від того, чи є ключ.
    delay = DELAY_WITH_KEY if get_api_key() else DELAY_WITHOUT_KEY

    # range(retries) дасть 0, 1, 2 — тобто три спроби.
    for attempt in range(retries):
        try:
            response = requests.get(API_URL, params=params, headers=headers, timeout=30)
        except requests.exceptions.RequestException as err:
            # Сюди потрапляємо, якщо взагалі не вдалося достукатися:
            # немає інтернету, DNS не резолвиться, вийшов таймаут.
            print(f"  Мережева помилка (спроба {attempt + 1}/{retries}): {err}")
            time.sleep(delay)
            continue

        # 200 = OK. Все добре, віддаємо розпакований JSON.
        if response.status_code == 200:
            return response.json()

        # 429 = Too Many Requests, 503 = Service Unavailable.
        # Це тимчасові помилки — має сенс зачекати і спробувати ще раз.
        if response.status_code in (429, 503):
            # Експоненційна затримка: 6 → 12 → 24 секунди.
            # Кожна наступна пауза вдвічі довша. Так роблять усі "дорослі" клієнти,
            # щоб не добивати сервер, якому і так погано.
            wait = delay * (2 ** attempt)
            print(f"  Сервер відповів {response.status_code}, чекаємо {wait:.0f} с...")
            time.sleep(wait)
            continue

        # 403 = Forbidden. Найчастіше — невірний або протермінований API-ключ.
        if response.status_code == 403:
            raise RuntimeError("403 Forbidden — перевірте значення NVD_API_KEY")

        # Будь-який інший код — не наша ситуація, зупиняємось.
        response.raise_for_status()

    raise RuntimeError(f"NVD не відповів після {retries} спроб")


def get_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """
    Дістає оцінку CVSS з блоку metrics.

    ЩО ТАКЕ CVSS?
    Common Vulnerability Scoring System — оцінка від 0.0 до 10.0.
    Чим більше, тим гірше. Текстовий рівень: LOW / MEDIUM / HIGH / CRITICAL.

    ЧОМУ ТУТ ЦІЛИЙ СПИСОК ВЕРСІЙ?
    Стандарт розвивається. Зараз в NVD одночасно живуть три покоління:
        cvssMetricV40 — CVSS 4.0, вийшов у листопаді 2023, найновіший
        cvssMetricV31 — CVSS 3.1, досі найпоширеніший
        cvssMetricV30 — CVSS 3.0, старіший
        cvssMetricV2  — CVSS 2.0, для нових CVE більше не рахується
    Ми перебираємо їх від нової до старої і беремо першу знайдену.

    УВАГА: оцінка 4.0 і 3.1 для однієї CVE може відрізнятися — формула змінилась.
    Не порівнюйте їх напряму і не змішуйте в одному SLA.

    Повертає:
        (оцінка, рівень, назва версії) або (None, None, None), якщо оцінки немає.
    """
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version)
        # Перевіряємо і наявність ключа, і те, що список не порожній.
        if not entries:
            continue

        cvss_data = entries[0].get("cvssData", {})
        return (
            cvss_data.get("baseScore"),
            cvss_data.get("baseSeverity"),
            version,
        )

    # Жодної версії не знайшли — це нормально для CVE зі статусом "Not Scheduled".
    return None, None, None


def get_description(cve: dict) -> str:
    """
    Дістає англомовний опис вразливості.

    У полі descriptions лежить список описів різними мовами.
    Нам потрібен той, де lang == "en".
    """
    descriptions = cve.get("descriptions", [])

    # Генераторний вираз усередині next() — це "знайди перший елемент, що підходить".
    # Другий аргумент next() — значення за замовчуванням, якщо нічого не знайшлось.
    return next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "Опис відсутній",
    )


def main() -> int:
    """
    Головна функція.

    Повертає код виходу: 0 — успіх, 1 — помилка.
    Це стандарт Unix: 0 означає "все добре". Так ваш скрипт можна
    використати у CI/CD або у bash-конвеєрі.
    """
    # sys.argv — список аргументів командного рядка.
    # sys.argv[0] — це завжди ім'я самого скрипта, тому дивимось на [1].
    keyword = sys.argv[1] if len(sys.argv) > 1 else "OpenSSH"

    # Одразу повідомляємо користувачу, у якому режимі працюємо.
    if get_api_key():
        print("Режим: з API-ключем (до 50 запитів / 30 с)")
    else:
        print("Режим: БЕЗ ключа (5 запитів / 30 с). Ключ безкоштовний — варто отримати.")

    print(f"Шукаємо: {keyword}\n")

    try:
        data = search_nvd(keyword, limit=5)
    except (RuntimeError, requests.exceptions.RequestException) as err:
        print(f"Помилка: {err}", file=sys.stderr)
        return 1

    # totalResults — скільки всього знайшлося в базі (а не скільки нам віддали).
    total = data.get("totalResults", 0)
    vulnerabilities = data.get("vulnerabilities", [])

    print(f"Всього у базі: {total}. Показуємо: {len(vulnerabilities)}")
    print("-" * 70)

    for item in vulnerabilities:
        cve = item.get("cve", {})

        cve_id = cve.get("id", "N/A")
        # vulnStatus — це саме те поле, яке показує, чи NVD взагалі
        # аналізував цю CVE: Analyzed / Awaiting Analysis / Not Scheduled / ...
        status = cve.get("vulnStatus", "Unknown")
        score, severity, version = get_cvss(cve.get("metrics", {}))
        description = get_description(cve)

        print(f"\n{cve_id}   [статус: {status}]")

        if score is None:
            print("  CVSS: немає оцінки від NVD")
        else:
            # {version[10:]} відрізає префікс "cvssMetric" і лишає "V31" / "V40".
            print(f"  CVSS: {score} ({severity}, {version[10:]})")

        print(f"  {description[:150]}...")
        print(f"  https://nvd.nist.gov/vuln/detail/{cve_id}")

    return 0


# Ця конструкція означає: "виконати main(), тільки якщо файл запущено напряму".
# Якщо хтось зробить `import 01_nvd_basic`, код нижче не спрацює.
if __name__ == "__main__":
    # sys.exit() передає код виходу операційній системі.
    sys.exit(main())

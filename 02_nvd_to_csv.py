#!/usr/bin/env python3
"""
02_nvd_to_csv.py — вивантаження вразливостей з NVD у CSV

ЩО РОБИТЬ ЦЕЙ СКРИПТ:
  1. Шукає в NVD усі вразливості за ключовим словом
  2. Проходить ВСІ сторінки результатів (пагінація), а не тільки першу
  3. Складає з них таблицю і зберігає у CSV
  4. Показує статистику: скільки CVE взагалі не мають оцінки CVSS

ЗАПУСК:
    python 02_nvd_to_csv.py                    # без аргументів -> шукає nginx
    python 02_nvd_to_csv.py "OpenSSH"          # своє ключове слово
    python 02_nvd_to_csv.py nginx --max 500    # більше записів

Аргументи необов'язкові саме для того, щоб скрипт запускався і кнопкою
"Run" у редакторі. Але кнопка не дозволяє передати аргументи взагалі —
щоб шукати щось своє, відкрийте термінал (у VS Code: Ctrl+`).

ЧОГО НАВЧАЄ ЦЕЙ СКРИПТ:
  - пагінація: API майже ніколи не віддає всі дані одним запитом
  - хто саме поставив оцінку (NVD, CNA виробника чи CISA) — тепер це важливо
  - чому "порожній score" — це не баг, а нормальний стан у 2026 році
"""

import argparse
import csv
import os
import sys
import time
from datetime import datetime

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "CyberCourse-Lesson9/2.0 (educational script)"

# Максимум, який NVD віддає за один запит для CVE API.
PAGE_SIZE = 2000

# Ключове слово, яке береться, якщо скрипт запустили без аргументів
# (наприклад, кнопкою "Run" у редакторі, а не з термінала).
DEFAULT_KEYWORD = "nginx"

# Порядок пріоритету версій CVSS: від найновішої до найстарішої.
CVSS_VERSIONS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# Назви колонок майбутньої таблиці. Виносимо в константу, щоб не дублювати
# один і той самий список у двох місцях (у функції збирання і у функції запису).
FIELDNAMES = [
    "cve_id",
    "published",
    "vuln_status",
    "cvss_version",
    "score",
    "severity",
    "score_source",
    "description",
    "link",
]


def get_headers() -> dict[str, str]:
    """Заголовки запиту; ключ береться зі змінної середовища NVD_API_KEY."""
    headers = {"User-Agent": USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def get_delay() -> float:
    """Пауза між запитами: 0.6 с з ключем, 6 с без ключа."""
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


def extract_cvss(metrics: dict) -> dict:
    """
    Дістає з блоку metrics оцінку, рівень, версію CVSS і джерело оцінки.

    ПРО ДЖЕРЕЛО ОЦІНКИ (поле "type" / "source").
    Раніше майже всі оцінки в NVD ставив сам NIST. Зараз їх ставлять:
      - Primary   — зазвичай CNA (той, хто випустив CVE: Cisco, Microsoft, Red Hat...)
      - Secondary — додаткове джерело
    NIST з квітня 2026 не дублює оцінку, якщо CNA вже її поставив.
    Практичний висновок: оцінки різних джерел можуть відрізнятися,
    і "офіційної єдиної" оцінки більше не існує.

    Повертає словник — так зручніше, ніж кортеж з чотирьох елементів,
    бо не треба пам'ятати порядок.
    """
    for version in CVSS_VERSIONS:
        entries = metrics.get(version)
        if not entries:
            continue

        entry = entries[0]
        cvss_data = entry.get("cvssData", {})

        return {
            "cvss_version": version[10:],                 # "cvssMetricV31" -> "V31"
            "score": cvss_data.get("baseScore"),
            "severity": cvss_data.get("baseSeverity"),
            "score_source": entry.get("source", "unknown"),
        }

    # Оцінки немає взагалі.
    return {
        "cvss_version": "",
        "score": "",
        "severity": "",
        "score_source": "",
    }


def format_date(raw: str) -> str:
    """
    Перетворює дату з формату API (2024-01-15T10:30:00.000) на 2024-01-15.

    Порожній рядок на вході — порожній на виході. Функція, яка не падає
    від відсутніх даних, економить години налагодження.
    """
    if not raw:
        return ""

    try:
        # Python 3.11+ уміє читати ISO-дати з "Z" напряму.
        # .replace() лишили для сумісності зі старішими версіями Python.
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d")
    except ValueError:
        # Формат несподіваний — краще повернути як є, ніж зламати весь скрипт.
        return raw


def fetch_page(keyword: str, start_index: int, page_size: int) -> dict:
    """
    Завантажує одну сторінку результатів.

    startIndex — це "з якого за рахунком запису почати".
    Саме так влаштована пагінація в NVD: не "сторінка №3",
    а "починаючи з запису 4000".
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(page_size),
        "startIndex": str(start_index),
    }

    response = requests.get(API_URL, params=params, headers=get_headers(), timeout=60)
    response.raise_for_status()
    return response.json()


def fetch_all(keyword: str, max_results: int) -> list[dict]:
    """
    Завантажує результати сторінка за сторінкою, поки не набереться max_results.

    ЧОМУ ЦЕ ВАЖЛИВО:
    Якщо ви попросите 20 записів для "nginx", ви отримаєте 20 найстаріших,
    а не 20 найважливіших. Люди роблять висновки по першій сторінці
    і помиляються. Або беріть усе, або свідомо фільтруйте запитом.
    """
    collected: list[dict] = []
    start_index = 0
    total = None

    while True:
        # min() тут, щоб не просити більше, ніж нам треба.
        page_size = min(PAGE_SIZE, max_results - len(collected))
        if page_size <= 0:
            break

        print(f"  Завантажую записи з {start_index}...")
        data = fetch_page(keyword, start_index, page_size)

        # totalResults приходить у кожній відповіді; запам'ятовуємо лише перший раз.
        if total is None:
            total = data.get("totalResults", 0)
            print(f"  Всього у базі за цим словом: {total}")

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            # Порожня сторінка означає, що дані скінчились.
            break

        collected.extend(vulnerabilities)
        start_index += len(vulnerabilities)

        # Дійшли до кінця результатів у базі.
        if start_index >= total:
            break

        # Пауза перед наступним запитом — інакше отримаємо 403 або 429.
        time.sleep(get_delay())

    return collected


def to_rows(vulnerabilities: list[dict]) -> list[dict]:
    """Перетворює "сирі" дані API на плоскі рядки таблиці."""
    rows = []

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        row = {
            "cve_id": cve_id,
            "published": format_date(cve.get("published", "")),
            "vuln_status": cve.get("vulnStatus", ""),
            # Опис ріжемо: у CSV довгі тексти з переносами рядків
            # перетворюють таблицю на кашу при відкритті в Excel.
            "description": description[:300].replace("\n", " "),
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

        # Додаємо до рядка чотири поля CVSS одним рухом.
        row.update(extract_cvss(cve.get("metrics", {})))

        rows.append(row)

    return rows


def save_csv(rows: list[dict], filename: str) -> None:
    """
    Записує рядки у CSV.

    ДВІ ДЕТАЛІ, ЯКІ ЛАМАЮТЬ CSV У НОВАЧКІВ:
      newline=""       — без цього у Windows між рядками з'являться порожні рядки
      encoding="utf-8-sig" — BOM, завдяки якому Excel правильно покаже кирилицю
    """
    if not rows:
        print("Немає даних для збереження.")
        return

    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nЗбережено {len(rows)} записів у {filename}")


def print_stats(rows: list[dict]) -> None:
    """
    Показує статистику по завантажених даних.

    Головне число тут — скільки CVE залишились БЕЗ оцінки.
    Саме воно ілюструє зміну політики NVD від 15 квітня 2026 року.
    """
    if not rows:
        return

    total = len(rows)
    without_score = sum(1 for r in rows if not r["score"])

    # Рахуємо, скільки разів зустрічається кожен статус.
    statuses: dict[str, int] = {}
    for row in rows:
        status = row["vuln_status"] or "Unknown"
        statuses[status] = statuses.get(status, 0) + 1

    print("\n" + "=" * 60)
    print("СТАТИСТИКА")
    print("=" * 60)
    print(f"Всього записів: {total}")
    print(f"Без оцінки CVSS: {without_score} ({without_score / total * 100:.1f}%)")

    print("\nСтатуси аналізу:")
    # sorted(..., key=..., reverse=True) — сортуємо за кількістю, від більшої.
    for status, count in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
        print(f"  {status}: {count}")

    critical = [r for r in rows if r["severity"] == "CRITICAL"]
    high = [r for r in rows if r["severity"] == "HIGH"]
    print(f"\nCRITICAL: {len(critical)}   HIGH: {len(high)}")


def main() -> int:
    # argparse — стандартний модуль для розбору аргументів командного рядка.
    # Він сам згенерує довідку для --help і сам перевірить типи.
    parser = argparse.ArgumentParser(description="Вивантаження CVE з NVD у CSV")

    # nargs="?" робить аргумент НЕОБОВ'ЯЗКОВИМ: якщо його не передали,
    # береться значення з default. Без цього скрипт неможливо запустити
    # кнопкою "Run" у VS Code / PyCharm — вони запускають файл без аргументів,
    # і argparse одразу завершує програму з помилкою.
    parser.add_argument(
        "keyword",
        nargs="?",
        default=DEFAULT_KEYWORD,
        help=f"ключове слово для пошуку (за замовч. {DEFAULT_KEYWORD})",
    )
    parser.add_argument("--max", type=int, default=200, help="максимум записів (за замовч. 200)")
    parser.add_argument("--out", default=None, help="ім'я CSV-файлу")
    args = parser.parse_args()

    # Якщо ім'я файлу не задане — робимо його з ключового слова.
    # .replace(" ", "_") прибирає пробіли, які ускладнюють роботу в терміналі.
    output = args.out or f"{args.keyword.replace(' ', '_').lower()}_cves.csv"

    # Якщо аргумент не передали — підказуємо, як шукати щось своє.
    # sys.argv містить лише ім'я скрипта, коли аргументів немає.
    if len(sys.argv) == 1:
        print(f"Аргумент не задано, використовую значення за замовчуванням: {DEFAULT_KEYWORD}")
        print("Щоб шукати інше, запустіть з термінала:")
        print("    python 02_nvd_to_csv.py nginx --max 100\n")

    print(f"Пошук: {args.keyword} (максимум {args.max} записів)")

    try:
        vulnerabilities = fetch_all(args.keyword, args.max)
    except requests.exceptions.RequestException as err:
        print(f"Помилка API: {err}", file=sys.stderr)
        return 1

    rows = to_rows(vulnerabilities)
    save_csv(rows, output)
    print_stats(rows)

    print("\nНаступний крок: перевірте ці CVE через 03_kev_epss.py —")
    print("оцінка CVSS сама по собі не каже, що атакують саме вас.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
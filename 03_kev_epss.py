#!/usr/bin/env python3
"""
03_kev_epss.py — пріоритезація CVE за реальним ризиком: KEV + EPSS

НАВІЩО ЦЕЙ СКРИПТ ІСНУЄ
Уявіть, що сканер знайшов у вас 800 вразливостей. Патчити всі 800 за тиждень
неможливо. Питання не в тому, "які вразливості небезпечні" (всі), а в тому,
"які з них ламають прямо зараз". CVSS на це питання не відповідає: він оцінює
теоретичну шкоду, а не ймовірність атаки. Тому додаємо два джерела:

  KEV  (CISA Known Exploited Vulnerabilities) — список CVE, для яких є
       ДОКАЗАНІ факти експлуатації в реальних атаках. Це факт, не прогноз.
       Приблизно 1600 записів проти сотень тисяч CVE загалом.

  EPSS (Exploit Prediction Scoring System від FIRST) — ймовірність від 0 до 1,
       що конкретну CVE спробують експлуатувати протягом наступних 30 днів.
       Це прогноз, який оновлюється щодня.

Формула, яку використовують у реальних командах:
  KEV                        -> P1, патч негайно (це вже відбувається)
  EPSS >= 0.5 і CVSS >= 7.0  -> P2, патч цього тижня
  EPSS >= 0.1                -> P3, патч у плановому циклі
  решта                      -> P4, у бэклог

ЗАПУСК:
    python 03_kev_epss.py CVE-2021-44228 CVE-2024-3400
    python 03_kev_epss.py --csv nginx_cves.csv          # колонка cve_id
    python 03_kev_epss.py --csv nginx_cves.csv --out priorities.csv

ЖОДЕН З ЦИХ API НЕ ПОТРЕБУЄ КЛЮЧА І НЕ МАЄ ЖОРСТКОГО RATE LIMIT.
"""

import argparse
import csv
import json
import sys
import time
from pathlib import Path

import requests

# ── Джерела даних ─────────────────────────────────────────────────────────────
# Основне джерело KEV — сайт CISA.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Запасне джерело: офіційне дзеркало CISA на GitHub. Стане в пригоді, якщо
# ваша мережа блокує .gov або CDN CISA віддає 403 (таке буває в CI).
KEV_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

EPSS_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "CyberCourse-Lesson9/2.0 (educational script)"

# Локальний кеш KEV. Файл ~1.5 МБ; качати його на кожен запуск — марно
# навантажувати чужий сервер. Кеш живе одну добу.
KEV_CACHE = Path("kev_cache.json")
KEV_CACHE_TTL = 24 * 60 * 60  # у секундах

# EPSS API приймає список CVE у параметрі cve через кому.
# Обмеження — 2000 символів на параметр. Один CVE ID ~ 15-18 символів,
# тому 100 штук за раз — безпечний розмір пачки.
EPSS_BATCH_SIZE = 100


def download_kev() -> dict:
    """
    Завантажує каталог KEV, з кешуванням на добу.

    ЩО ТУТ ВАРТО ЗАПАМ'ЯТАТИ:
    Кеш — це не оптимізація "на потім", а базова ввічливість до чужого API
    і захист від того, що ваш скрипт перестане працювати під час інциденту,
    коли сервіс перевантажений.
    """
    # Крок 1: перевіряємо, чи є свіжий кеш.
    if KEV_CACHE.exists():
        # .stat().st_mtime — час останньої зміни файлу (у секундах з 1970 року).
        age = time.time() - KEV_CACHE.stat().st_mtime
        if age < KEV_CACHE_TTL:
            print(f"KEV: беру з кешу ({age / 3600:.1f} год тому)")
            # encoding="utf-8" вказуємо явно: на Windows типове кодування інше,
            # і без цього рядка скрипт впаде на файлі з не-ASCII символами.
            return json.loads(KEV_CACHE.read_text(encoding="utf-8"))

    # Крок 2: кешу немає або він застарів — качаємо.
    headers = {"User-Agent": USER_AGENT}

    for url in (KEV_URL, KEV_MIRROR_URL):
        try:
            print(f"KEV: завантажую з {url.split('/')[2]}...")
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as err:
            print(f"  не вдалось ({err}), пробую наступне джерело")
            continue

        # Зберігаємо у кеш.
        KEV_CACHE.write_text(json.dumps(data), encoding="utf-8")
        return data

    raise RuntimeError("Не вдалося завантажити KEV з жодного джерела")


def build_kev_index(kev_data: dict) -> dict[str, dict]:
    """
    Перетворює список KEV на словник {CVE ID -> запис}.

    ЧОМУ СЛОВНИК, А НЕ СПИСОК?
    Пошук у списку — це перебір: щоб перевірити 800 CVE проти 1600 записів,
    доведеться зробити 1.28 млн порівнянь. Пошук у словнику — миттєвий
    (складність O(1) проти O(n)). Це та сама ідея, що й індекс у базі даних.
    """
    index = {}

    for entry in kev_data.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if cve_id:
            index[cve_id] = entry

    return index


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Отримує EPSS-оцінки для списку CVE.

    Повертає словник {CVE ID -> {"epss": float, "percentile": float}}.
    CVE, яких немає у відповіді, просто не потраплять у словник —
    це нормально для дуже свіжих або дуже старих ID.
    """
    scores: dict[str, dict] = {}
    headers = {"User-Agent": USER_AGENT}

    # range(start, stop, step) з кроком EPSS_BATCH_SIZE ріже список на пачки:
    # 0, 100, 200, ... Далі cve_ids[i:i + 100] бере зріз потрібного розміру.
    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i:i + EPSS_BATCH_SIZE]

        params = {"cve": ",".join(batch)}

        try:
            response = requests.get(EPSS_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print(f"  EPSS: помилка для пачки {i // EPSS_BATCH_SIZE + 1}: {err}")
            continue

        for item in response.json().get("data", []):
            # API повертає числа РЯДКАМИ ("0.009540000"), тому float() обов'язковий.
            # Це класична пастка: без перетворення порівняння "0.9" >= 0.5
            # впаде з TypeError або, ще гірше, дасть неочікуваний результат.
            scores[item["cve"]] = {
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
            }

        # Невелика пауза між пачками — жорсткого ліміту немає, але поводимось чемно.
        time.sleep(0.5)

    return scores


def prioritize(in_kev: bool, epss: float | None, cvss: float | None) -> tuple[str, str]:
    """
    Визначає пріоритет однієї CVE.

    Повертає (пріоритет, причина).

    ПОРЯДОК ПЕРЕВІРОК ТУТ КРИТИЧНО ВАЖЛИВИЙ.
    KEV перевіряємо ПЕРШИМ, бо це доказ, а не прогноз. Вразливість може мати
    CVSS 6.5 і EPSS 0.02 — і все одно бути в KEV, бо нею вже ламають.
    Найвідоміший приклад такого роду: старі CVE у мережевих пристроях,
    яким формальна оцінка занижена, але їх масово експлуатують.
    """
    if in_kev:
        return "P1", "у каталозі CISA KEV — експлуатація підтверджена"

    # `epss is not None` обов'язково: без цього порівняння None >= 0.5 впаде.
    # Крім того, 0.0 — це валідне значення, а `if epss:` вважало б його хибним.
    if epss is not None and epss >= 0.5:
        if cvss is not None and cvss >= 7.0:
            return "P2", f"EPSS {epss:.2%} + CVSS {cvss}"
        return "P2", f"EPSS {epss:.2%} — висока ймовірність експлуатації"

    if epss is not None and epss >= 0.1:
        return "P3", f"EPSS {epss:.2%} — помітна ймовірність"

    if cvss is not None and cvss >= 9.0:
        return "P3", f"CVSS {cvss} — критична за наслідками, але атак не видно"

    return "P4", "низька ймовірність експлуатації"


def read_cves_from_csv(path: str) -> list[str]:
    """
    Читає CVE ID з CSV-файлу (з колонки cve_id або CVE ID).

    Так результат скрипта 02_nvd_to_csv.py напряму подається на вхід цьому.
    Скрипти, які вміють передавати дані одне одному, — це і є автоматизація.
    """
    cves = []

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        for row in reader:
            # Пробуємо кілька варіантів назви колонки — файли бувають різні.
            value = row.get("cve_id") or row.get("CVE ID") or row.get("cve")
            if value and value.startswith("CVE-"):
                cves.append(value.strip())

    # dict.fromkeys() прибирає дублікати, ЗБЕРІГАЮЧИ порядок
    # (на відміну від set(), який порядок втрачає).
    return list(dict.fromkeys(cves))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Пріоритезація CVE за KEV та EPSS",
    )
    parser.add_argument("cves", nargs="*", help="CVE ID через пробіл")
    parser.add_argument("--csv", help="CSV-файл з колонкою cve_id")
    parser.add_argument("--out", default="cve_priorities.csv", help="куди зберегти результат")
    args = parser.parse_args()

    # Збираємо список CVE або з аргументів, або з файлу.
    cve_ids = list(args.cves)
    if args.csv:
        cve_ids.extend(read_cves_from_csv(args.csv))

    cve_ids = list(dict.fromkeys(cve_ids))

    if not cve_ids:
        print("Не вказано жодної CVE. Приклад:")
        print("  python 03_kev_epss.py CVE-2021-44228 CVE-2024-3400")
        return 1

    print(f"Перевіряю {len(cve_ids)} CVE\n")

    # ── Крок 1: KEV ───────────────────────────────────────────────────────────
    try:
        kev_data = download_kev()
    except RuntimeError as err:
        print(f"Помилка: {err}", file=sys.stderr)
        return 1

    kev_index = build_kev_index(kev_data)
    print(f"KEV: {len(kev_index)} записів, версія каталогу {kev_data.get('catalogVersion')}")

    # ── Крок 2: EPSS ──────────────────────────────────────────────────────────
    print("EPSS: запитую оцінки...")
    epss_scores = fetch_epss(cve_ids)
    print(f"EPSS: отримано оцінок {len(epss_scores)} з {len(cve_ids)}\n")

    # ── Крок 3: зводимо все разом ─────────────────────────────────────────────
    rows = []

    for cve_id in cve_ids:
        kev_entry = kev_index.get(cve_id)
        epss_entry = epss_scores.get(cve_id, {})

        epss = epss_entry.get("epss")
        percentile = epss_entry.get("percentile")

        priority, reason = prioritize(
            in_kev=kev_entry is not None,
            epss=epss,
            cvss=None,  # CVSS тут не тягнемо, щоб не бити по NVD; див. 06_risk_report.py
        )

        rows.append({
            "cve_id": cve_id,
            "priority": priority,
            "in_kev": "так" if kev_entry else "ні",
            "kev_date_added": kev_entry.get("dateAdded", "") if kev_entry else "",
            "ransomware": kev_entry.get("knownRansomwareCampaignUse", "") if kev_entry else "",
            "epss": f"{epss:.5f}" if epss is not None else "",
            "epss_percentile": f"{percentile:.3f}" if percentile is not None else "",
            "reason": reason,
        })

    # Сортуємо: спочатку P1, потім за EPSS від більшого.
    # Ключ сортування — кортеж: Python порівнює його поелементно.
    rows.sort(key=lambda r: (r["priority"], -float(r["epss"] or 0)))

    # ── Крок 4: вивід ─────────────────────────────────────────────────────────
    print(f"{'CVE':<20} {'PRIO':<6} {'KEV':<5} {'EPSS':<9} ПРИЧИНА")
    print("-" * 90)

    for row in rows:
        epss_display = f"{float(row['epss']):.2%}" if row["epss"] else "—"
        print(
            f"{row['cve_id']:<20} {row['priority']:<6} {row['in_kev']:<5} "
            f"{epss_display:<9} {row['reason']}"
        )

    # Підсумок по пріоритетах.
    print()
    for level in ("P1", "P2", "P3", "P4"):
        count = sum(1 for r in rows if r["priority"] == level)
        if count:
            print(f"  {level}: {count}")

    # ── Крок 5: збереження ────────────────────────────────────────────────────
    with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nЗбережено у {args.out}")
    print(f"Кеш KEV: {KEV_CACHE.resolve()} (видаліть файл, щоб оновити примусово)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

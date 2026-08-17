#!/usr/bin/env python3
"""
06_risk_report.py — підсумковий скрипт: інвентар -> NVD -> KEV -> EPSS -> звіт

Це еталонне рішення домашнього завдання. Воно збирає докупи все,
що ми робили у скриптах 01-05, і показує, як виглядає маленький,
але справжній конвеєр управління вразливостями:

    04_inventory.py  ->  inventory.json
                              |
                              v
                    пошук CVE у NVD (за назвою + версією)
                              |
                              v
              збагачення: KEV (факт атак) + EPSS (прогноз)
                              |
                              v
              пріоритезація P1-P4 -> risk_report.csv

ЗАПУСК:
    python 04_inventory.py                       # спочатку зібрати інвентар
    python 06_risk_report.py                     # потім побудувати звіт
    python 06_risk_report.py --limit 10 --per-app 5

ЧЕСНЕ ЗАСТЕРЕЖЕННЯ ПРО ТОЧНІСТЬ
Пошук за ключовим словом дає багато хибних збігів: запит "Chrome" знайде
і Google Chrome, і сторонні продукти зі словом Chrome в описі. Промислові
сканери працюють інакше — через CPE (Common Platform Enumeration), тобто
точний ідентифікатор продукту і версії. Ми свідомо йдемо простішим шляхом,
щоб зрозуміти механіку. Але подавати такий звіт як результат аудиту не можна:
це навчальна оцінка, а не факт.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "CyberCourse-Lesson9/2.0 (educational script)"
KEV_CACHE = Path("kev_cache.json")

CVSS_VERSIONS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


# ── Блок 1: допоміжні функції для NVD ─────────────────────────────────────────

def nvd_headers() -> dict[str, str]:
    """Заголовки для NVD; ключ — зі змінної середовища."""
    headers = {"User-Agent": USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def nvd_delay() -> float:
    """Пауза між запитами до NVD залежно від наявності ключа."""
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


def extract_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Дістає оцінку і рівень CVSS, починаючи з найновішої версії стандарту."""
    for version in CVSS_VERSIONS:
        entries = metrics.get(version)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity")

    return None, None


def search_cves(app_name: str, limit: int) -> list[dict]:
    """
    Шукає CVE для однієї програми.

    Порожній список у відповідь на помилку — свідоме рішення: одна невдала
    програма не повинна зупиняти обробку решти сорока.
    """
    params = {"keywordSearch": app_name, "resultsPerPage": str(limit)}

    try:
        response = requests.get(NVD_URL, params=params, headers=nvd_headers(), timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print(f"    помилка NVD: {err}")
        return []

    results = []

    for item in response.json().get("vulnerabilities", []):
        cve = item.get("cve", {})
        score, severity = extract_cvss(cve.get("metrics", {}))

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        results.append({
            "app": app_name,
            "cve_id": cve.get("id", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "cvss": score,
            "severity": severity or "",
            "published": (cve.get("published") or "")[:10],
            "description": description[:200].replace("\n", " "),
        })

    return results


# ── Блок 2: збагачення KEV та EPSS ────────────────────────────────────────────

def load_kev() -> set[str]:
    """
    Повертає множину CVE ID, які є у каталозі KEV.

    set (множина) — правильна структура для питання "чи є елемент у наборі".
    Перевірка `cve in kev_set` виконується за постійний час незалежно від того,
    1600 там записів чи 160 000.
    """
    if KEV_CACHE.exists() and time.time() - KEV_CACHE.stat().st_mtime < 86400:
        data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
    else:
        data = None

        for url in (KEV_URL, KEV_MIRROR_URL):
            try:
                response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=60)
                response.raise_for_status()
                data = response.json()
                KEV_CACHE.write_text(json.dumps(data), encoding="utf-8")
                break
            except requests.exceptions.RequestException:
                continue

        if data is None:
            print("  KEV недоступний — продовжую без нього")
            return set()

    # Генератор множини: {вираз for елемент in колекція}
    return {entry["cveID"] for entry in data.get("vulnerabilities", []) if entry.get("cveID")}


def load_epss(cve_ids: list[str]) -> dict[str, float]:
    """Повертає {CVE ID -> ймовірність експлуатації} для переданих CVE."""
    scores: dict[str, float] = {}

    for i in range(0, len(cve_ids), 100):
        batch = cve_ids[i:i + 100]

        try:
            response = requests.get(
                EPSS_URL,
                params={"cve": ",".join(batch)},
                headers={"User-Agent": USER_AGENT},
                timeout=30,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print(f"  EPSS недоступний: {err}")
            continue

        for item in response.json().get("data", []):
            scores[item["cve"]] = float(item["epss"])

        time.sleep(0.5)

    return scores


def priority(in_kev: bool, epss: float, cvss: float | None) -> str:
    """
    Пріоритет однієї знахідки. Порядок перевірок = порядок важливості.

    pd.isna() потрібен, бо pandas перетворює відсутні числа на NaN,
    а NaN — підступна штука: NaN >= 7.0 завжди False, і жодної помилки
    при цьому не буде. Такі баги знаходять місяцями.
    """
    if in_kev:
        return "P1"

    if epss >= 0.5:
        return "P2"

    if epss >= 0.1:
        return "P3"

    if cvss is not None and not pd.isna(cvss) and cvss >= 9.0:
        return "P3"

    return "P4"


# ── Блок 3: головний конвеєр ──────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Звіт про ризики за інвентарем")
    parser.add_argument("--inventory", default="inventory.json", help="файл від 04_inventory.py")
    parser.add_argument("--limit", type=int, default=10, help="скільки програм перевірити")
    parser.add_argument("--per-app", type=int, default=5, help="скільки CVE на програму")
    parser.add_argument("--out", default="risk_report.csv", help="файл звіту")
    args = parser.parse_args()

    # ── Крок 1: читаємо інвентар ──────────────────────────────────────────────
    inventory_path = Path(args.inventory)

    if not inventory_path.exists():
        print(f"Немає файлу {inventory_path}. Спочатку запустіть 04_inventory.py")
        return 1

    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    apps = inventory[:args.limit]

    print(f"Програм у звіті: {len(apps)} (з {len(inventory)} в інвентарі)")
    print(f"Пауза між запитами: {nvd_delay()} с\n")

    # ── Крок 2: шукаємо CVE ───────────────────────────────────────────────────
    findings: list[dict] = []

    for i, app in enumerate(apps, start=1):
        name = app["name"]
        version = app.get("version") or "—"

        print(f"[{i}/{len(apps)}] {name} {version}")

        results = search_cves(name, args.per_app)

        # Версію з інвентаря носимо із собою в кожному рядку —
        # без неї звіт неможливо перевірити вручну.
        for row in results:
            row["installed_version"] = version

        findings.extend(results)
        print(f"    знайдено CVE: {len(results)}")

        # Пауза перед наступним запитом; після останнього — не потрібна.
        if i < len(apps):
            time.sleep(nvd_delay())

    if not findings:
        print("\nЖодної CVE не знайдено.")
        return 0

    # ── Крок 3: збагачуємо ────────────────────────────────────────────────────
    print(f"\nВсього знахідок: {len(findings)}")
    print("Завантажую KEV...")
    kev = load_kev()
    print(f"  у KEV записів: {len(kev)}")

    cve_ids = sorted({f["cve_id"] for f in findings if f["cve_id"]})
    print(f"Запитую EPSS для {len(cve_ids)} унікальних CVE...")
    epss = load_epss(cve_ids)
    print(f"  отримано оцінок: {len(epss)}")

    # ── Крок 4: збираємо таблицю ──────────────────────────────────────────────
    # DataFrame — це таблиця pandas: рядки і названі колонки, як у Excel.
    df = pd.DataFrame(findings)

    # .map() застосовує функцію до кожного значення колонки і повертає нову колонку.
    df["in_kev"] = df["cve_id"].map(lambda c: c in kev)

    # .get(c, 0.0) — якщо для CVE немає оцінки EPSS, вважаємо її нулем.
    # Це свідоме припущення: "немає даних" тут трактуємо як "сигналів атак немає".
    df["epss"] = df["cve_id"].map(lambda c: epss.get(c, 0.0))

    # axis=1 означає "застосувати функцію до кожного РЯДКА" (а не до кожної колонки).
    df["priority"] = df.apply(
        lambda row: priority(row["in_kev"], row["epss"], row["cvss"]),
        axis=1,
    )

    # Сортуємо: спочатку за пріоритетом (P1 < P2 < P3 < P4 як рядки),
    # усередині пріоритету — за EPSS від більшого до меншого.
    df = df.sort_values(
        ["priority", "epss"],
        ascending=[True, False],
    )

    # ── Крок 5: виводимо підсумок ─────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("ПІДСУМОК")
    print("=" * 70)

    # value_counts() рахує, скільки разів зустрічається кожне значення.
    # .sort_index() ставить їх у порядку P1, P2, P3, P4.
    for level, count in df["priority"].value_counts().sort_index().items():
        print(f"  {level}: {count}")

    # Скільки знахідок узагалі не мають оцінки CVSS від NVD —
    # ілюстрація нової політики NVD від квітня 2026 року.
    no_score = df["cvss"].isna().sum()
    print(f"\nБез оцінки CVSS: {no_score} з {len(df)}")

    # Показуємо все, що потрапило у P1 та P2 — це і є робота на цей тиждень.
    urgent = df[df["priority"].isin(["P1", "P2"])]

    if urgent.empty:
        print("\nP1/P2 немає — терміново патчити нічого. Перевірте ще раз завтра.")
    else:
        print(f"\nПотребує уваги ({len(urgent)}):")
        for _, row in urgent.head(15).iterrows():
            kev_mark = "KEV" if row["in_kev"] else "   "
            cvss_display = "—" if pd.isna(row["cvss"]) else f"{row['cvss']}"
            print(
                f"  {row['priority']} {kev_mark} {row['cve_id']:<18} "
                f"EPSS {row['epss']:.1%}  CVSS {cvss_display:<5} {row['app']}"
            )

    # ── Крок 6: зберігаємо ────────────────────────────────────────────────────
    df.to_csv(args.out, index=False, encoding="utf-8-sig")
    print(f"\nЗвіт збережено у {args.out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

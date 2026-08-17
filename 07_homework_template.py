#!/usr/bin/env python3
"""
07_homework_template.py — шаблон домашнього завдання

ЗАВДАННЯ
Написати скрипт, який будує міні-звіт про ризики для вашого комп'ютера:

  1. Бере 5 програм зі свого інвентаря (04_inventory.py -> inventory.json)
  2. Для кожної шукає до 3 CVE у NVD
  3. Перевіряє кожну знайдену CVE у каталозі CISA KEV
  4. Отримує для кожної CVE оцінку EPSS
  5. Присвоює пріоритет P1-P4 і зберігає результат у CSV
  6. У README.md пише 5-7 речень: які знахідки виявились хибними і чому

ЩО ОЦІНЮЄТЬСЯ (25 балів)
  5  — скрипт запускається і не падає на порожніх/відсутніх даних
  5  — коректний rate limiting (без нього ви отримаєте 403 від NVD)
  5  — KEV та EPSS реально використані, а не просто згадані
  5  — CSV має всі потрібні колонки і відкривається в Excel без каші
  5  — README з чесним аналізом хибних збігів

ПІДКАЗКИ
  - Секрети не комітити. NVD_API_KEY — тільки зі змінної середовища.
  - Перед комітом: git status. Переконайтесь, що .env і *.csv не в індексі.
  - Якщо NVD віддає 403 — ви занадто швидкі. 6 секунд між запитами без ключа.
"""

# Ці імпорти вам знадобляться у TODO. Позначка noqa каже лінтеру ruff
# "я знаю, що зараз вони не використані" — приберіть її, коли напишете код.
import csv  # noqa: F401
import os
import time  # noqa: F401

import requests  # noqa: F401

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# Замініть на 5 реальних програм зі свого inventory.json
MY_APPS = [
    {"name": "Firefox", "version": "141.0"},
    {"name": "Google Chrome", "version": "138.0"},
    {"name": "VLC", "version": "3.0.21"},
    {"name": "7-Zip", "version": "24.09"},
    {"name": "Notepad++", "version": "8.7"},
]


def get_delay() -> float:
    """Пауза між запитами до NVD: 6 с без ключа, 0.6 с з ключем."""
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


def search_nvd(app_name: str, limit: int = 3) -> list[dict]:
    """
    TODO 1: знайти CVE для програми.

    Кроки:
      1. Сформувати params: keywordSearch та resultsPerPage
      2. Виконати requests.get() з timeout і заголовком User-Agent
      3. Обгорнути виклик у try/except requests.exceptions.RequestException
      4. Для кожного елемента "vulnerabilities" дістати:
         id, vulnStatus, оцінку CVSS (v4.0 -> v3.1 -> v3.0), опис
      5. Повернути список словників

    Пам'ятайте: у частини CVE оцінки CVSS не буде взагалі. Це не помилка.
    """
    return []


def load_kev() -> set[str]:
    """
    TODO 2: завантажити каталог KEV і повернути множину CVE ID.

    Кроки:
      1. requests.get(KEV_URL, timeout=60)
      2. Дістати список за ключем "vulnerabilities"
      3. Зібрати множину значень "cveID"

    Бонус (+0 балів, але правильно): зберегти файл на диск і не качати
    його повторно, якщо він свіжіший за добу.
    """
    return set()


def load_epss(cve_ids: list[str]) -> dict[str, float]:
    """
    TODO 3: отримати EPSS-оцінки для списку CVE.

    Кроки:
      1. Об'єднати ID через кому: ",".join(cve_ids)
      2. requests.get(EPSS_URL, params={"cve": ...})
      3. З відповіді взяти список "data"
      4. Повернути {item["cve"]: float(item["epss"])}

    Увага: API повертає числа РЯДКАМИ. Без float() порівняння працюватиме дивно.
    """
    return {}


def get_priority(in_kev: bool, epss: float, cvss: float | None) -> str:
    """
    TODO 4: реалізувати правила пріоритезації.

        KEV                        -> "P1"
        EPSS >= 0.5                -> "P2"
        EPSS >= 0.1                -> "P3"
        CVSS >= 9.0                -> "P3"
        інакше                     -> "P4"

    Порядок перевірок важливий. Подумайте, чому KEV перевіряється першим.
    """
    return "P4"


def save_csv(rows: list[dict], filename: str) -> None:
    """
    TODO 5: зберегти результат у CSV.

    Колонки: app, installed_version, cve_id, cvss, severity, in_kev, epss, priority

    Не забудьте: newline="" та encoding="utf-8-sig".
    """


def main() -> None:
    print("Домашнє завдання: звіт про ризики\n")

    all_rows: list[dict] = []

    for i, app in enumerate(MY_APPS, start=1):
        print(f"[{i}/{len(MY_APPS)}] {app['name']} {app['version']}")

        # TODO 6: викликати search_nvd(), додати результати до all_rows
        # TODO 7: не забути про паузу time.sleep(get_delay()) між запитами

    # TODO 8: завантажити KEV, отримати EPSS, проставити пріоритети
    # TODO 9: викликати save_csv() і вивести підсумок по P1/P2/P3/P4

    print(f"\nЗібрано рядків: {len(all_rows)}")


if __name__ == "__main__":
    main()

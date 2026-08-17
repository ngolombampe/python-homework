#!/usr/bin/env python3
"""
05_osv_scan.py — перевірка ваших власних Python-залежностей через OSV.dev

ЧОМУ ОКРЕМИЙ СКРИПТ ДЛЯ ЗАЛЕЖНОСТЕЙ
NVD добре знає про "великі" продукти: nginx, OpenSSH, Windows. Але коли
йдеться про бібліотеку з PyPI або npm, зручніше питати OSV.dev — базу
від Google, яка агрегує GitHub Security Advisories, PyPA, Go, Rust, Alpine
та десяток інших джерел. Вона розуміє діапазони версій пакета і одразу
каже, у якій версії проблему виправлено.

ПЕРЕВАГИ OSV.dev:
  - безкоштовно, без ключа, без реєстрації і без жорсткого rate limit
  - розуміє версії пакетів (а не тільки назви, як keywordSearch у NVD)
  - один POST-запит перевіряє до 1000 пакетів
  - каже "виправлено у версії X", а не просто "тут є проблема"

ЗАПУСК:
    python 05_osv_scan.py                     # перевірити встановлені пакети
    python 05_osv_scan.py requirements.txt    # перевірити файл залежностей

ЩО ЦЕ ІЛЮСТРУЄ ДЛЯ КУРСУ:
supply chain security. Ваш код може бути ідеальним, але ви тягнете за собою
50 чужих бібліотек, і атакувати будуть саме їх.
"""

import argparse
import json
import sys
from importlib import metadata

import requests

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

USER_AGENT = "CyberCourse-Lesson9/2.0 (educational script)"

# OSV приймає до 1000 запитів у одній пачці. Беремо менше, щоб відповідь
# швидше приходила і легше було зрозуміти, де саме сталась помилка.
BATCH_SIZE = 200


def get_installed_packages() -> list[tuple[str, str]]:
    """
    Повертає список (назва, версія) встановлених Python-пакетів.

    importlib.metadata — стандартний модуль, який читає метадані пакетів
    прямо з віртуального середовища. Це набагато краще, ніж запускати
    `pip list` через subprocess: не залежить від того, як називається pip,
    працює швидше і не ламається у нестандартних середовищах.
    """
    packages = []

    for dist in metadata.distributions():
        # У рідкісних випадках метадані пошкоджені, тому обгортаємо в try.
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except (KeyError, TypeError):
            continue

        if name and version:
            packages.append((name, version))

    return sorted(set(packages))


def parse_requirements(path: str) -> list[tuple[str, str]]:
    """
    Розбирає requirements.txt і бере звідти рядки виду `пакет==версія`.

    Свідомо підтримуємо лише закріплені (`pinned`) версії з `==`.
    Рядок `requests>=2.0` не каже, яка версія стоїть насправді,
    а перевіряти "щось із діапазону" безглуздо. Це і є аргумент
    на користь lock-файлів: без них ви не знаєте, що у вас реально стоїть.
    """
    packages = []

    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Пропускаємо порожні рядки, коментарі та опції (-r, --index-url).
            if not line or line.startswith(("#", "-")):
                continue

            if "==" not in line:
                print(f"  Пропускаю (немає точної версії): {line}")
                continue

            # split("==", 1) ділить рядок за ПЕРШИМ входженням.
            name, version = line.split("==", 1)

            # Прибираємо хвости: `; python_version < "3.11"` та коментарі.
            version = version.split(";")[0].split("#")[0].strip()
            packages.append((name.strip(), version))

    return packages


def query_osv(packages: list[tuple[str, str]]) -> dict[str, list[str]]:
    """
    Питає OSV, чи є вразливості у переданих пакетах.

    Повертає словник {"пакет==версія" -> [список ID вразливостей]}.

    КЛЮЧОВА ДЕТАЛЬ API:
    відповідь results приходить У ТОМУ САМОМУ ПОРЯДКУ, що й запити,
    включно з порожніми елементами. Тому не можна "викинути порожні
    і зіставити решту" — зіставляти треба строго за індексом,
    інакше вразливості поїдуть не тим пакетам.
    """
    findings: dict[str, list[str]] = {}
    headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}

    for i in range(0, len(packages), BATCH_SIZE):
        batch = packages[i:i + BATCH_SIZE]

        # Формуємо тіло запиту згідно зі схемою OSV.
        # ecosystem "PyPI" пишеться саме так — з великими P і I, назви чутливі до регістру.
        payload = {
            "queries": [
                {
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                }
                for name, version in batch
            ]
        }

        try:
            response = requests.post(
                OSV_QUERYBATCH_URL,
                # json=payload сам зробить json.dumps і поставить правильний Content-Type
                json=payload,
                headers=headers,
                timeout=60,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print(f"  Помилка OSV: {err}", file=sys.stderr)
            continue

        results = response.json().get("results", [])

        # zip() поєднує два списки попарно: перший запит з першим результатом і т.д.
        for (name, version), result in zip(batch, results):
            vulns = result.get("vulns", [])
            if vulns:
                findings[f"{name}=={version}"] = [v["id"] for v in vulns]

    return findings


def get_vuln_details(vuln_id: str) -> dict:
    """
    Дістає повний опис однієї вразливості за її ID.

    ID може бути різного типу: GHSA-xxxx (GitHub), PYSEC-xxxx (PyPA),
    CVE-xxxx (класичний). OSV зводить їх усі в одну модель.
    """
    headers = {"User-Agent": USER_AGENT}

    try:
        response = requests.get(OSV_VULN_URL + vuln_id, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return {}


def extract_fixed_version(details: dict) -> str:
    """
    Шукає у записі вразливості версію, в якій її виправили.

    Структура affected -> ranges -> events виглядає складно, але логіка проста:
    це послідовність подій "з версії X проблема з'явилась",
    "у версії Y її виправили". Нас цікавить подія "fixed".
    """
    for affected in details.get("affected", []):
        for range_info in affected.get("ranges", []):
            for event in range_info.get("events", []):
                if "fixed" in event:
                    return event["fixed"]

    return "невідомо"


def main() -> int:
    parser = argparse.ArgumentParser(description="Перевірка Python-залежностей через OSV.dev")
    parser.add_argument("requirements", nargs="?", help="шлях до requirements.txt (необов'язково)")
    parser.add_argument("--details", action="store_true", help="показати опис кожної знахідки")
    parser.add_argument("--out", default="osv_findings.json", help="куди зберегти результат")
    args = parser.parse_args()

    if args.requirements:
        print(f"Читаю {args.requirements}")
        packages = parse_requirements(args.requirements)
    else:
        print("Перевіряю пакети, встановлені у поточному середовищі")
        packages = get_installed_packages()

    if not packages:
        print("Пакетів не знайдено.")
        return 1

    print(f"Пакетів до перевірки: {len(packages)}\n")

    findings = query_osv(packages)

    if not findings:
        print("Вразливостей не знайдено. Це добре, але означає лише")
        print("'нічого не відомо саме зараз' — перевіряйте регулярно.")
        return 0

    print(f"Знайдено проблемних пакетів: {len(findings)}\n")
    print("=" * 70)

    for package, vuln_ids in sorted(findings.items()):
        print(f"\n{package}")

        for vuln_id in vuln_ids:
            print(f"  {vuln_id}")

            if args.details:
                details = get_vuln_details(vuln_id)
                summary = details.get("summary", "без опису")
                fixed = extract_fixed_version(details)
                print(f"    {summary}")
                print(f"    Виправлено у версії: {fixed}")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    print(f"\n\nЗбережено у {args.out}")
    print("\nЩо робити далі:")
    print("  1. Оновити пакети до виправлених версій")
    print("  2. Додати таку перевірку в CI (pip-audit, uv audit або osv-scanner)")
    print("  3. Не оновлювати наосліп — читати changelog, тестувати")
    return 0


if __name__ == "__main__":
    sys.exit(main())

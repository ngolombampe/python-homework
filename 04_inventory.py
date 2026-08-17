#!/usr/bin/env python3
"""
04_inventory.py — інвентаризація встановленого ПЗ (Windows / macOS / Linux)

ЧОМУ ЦЕ ПЕРШИЙ КРОК БУДЬ-ЯКОЇ ПРОГРАМИ УПРАВЛІННЯ ВРАЗЛИВОСТЯМИ
Не можна захистити те, про існування чого ви не знаєте. Перший контроль
у будь-якому фреймворку (CIS Controls №1, NIST CSF "Identify") — це інвентар.
Спочатку список активів, і лише потім сканування.

ЩО ЗМІНИЛОСЬ ПОРІВНЯНО ЗІ СТАРОЮ ВЕРСІЄЮ ЦЬОГО СКРИПТА:
  1. Збираємо ВЕРСІЇ, а не лише назви. Без версії неможливо сказати,
     чи стосується вас CVE: "Firefox" вразливий, "Firefox 141.0" — можливо, ні.
  2. Прибрали shell=True. Це не косметика, це вимога безпеки (див. нижче).
  3. На macOS читаємо Info.plist напряму замість запуску зовнішніх команд.
  4. Результат зберігається у JSON, придатний для подальшої обробки.

ЗАПУСК:
    python 04_inventory.py
    python 04_inventory.py --out my_inventory.json --limit 30
"""

import argparse
import json
import platform
import plistlib
import subprocess
import sys
from pathlib import Path

# Скільки секунд чекати на зовнішню команду, перш ніж вважати її зависшою.
# Без таймауту ваш скрипт може висіти вічно на команді, яка чекає вводу.
COMMAND_TIMEOUT = 120


# ══════════════════════════════════════════════════════════════════════════════
#  ВІДСТУП ПРО БЕЗПЕКУ: чому тут ніде немає shell=True
# ══════════════════════════════════════════════════════════════════════════════
#
#  НЕБЕЗПЕЧНО:
#      subprocess.run(f"find /Applications -name '{user_input}'", shell=True)
#
#  Якщо user_input дорівнює:  x'; rm -rf ~; echo '
#  то оболонка виконає ТРИ команди, і друга з них видалить домашню теку.
#  Це називається command injection і входить у CWE-78.
#
#  БЕЗПЕЧНО:
#      subprocess.run(["find", "/Applications", "-name", user_input])
#
#  Тут аргументи передаються процесу напряму, як масив рядків.
#  Оболонки в ланцюжку немає — інтерпретувати ';' та '|' нікому.
#
#  Правило: shell=True потрібен ЛИШЕ тоді, коли вам справді потрібні
#  можливості оболонки (конвеєри, підстановки). У 95% випадків — не потрібні.
#  А якщо потрібні — не підставляйте туди дані, які прийшли ззовні.
# ══════════════════════════════════════════════════════════════════════════════


def run_command(command: list[str]) -> str:
    """
    Безпечно запускає зовнішню команду і повертає її stdout.

    Параметр command — це СПИСОК, а не рядок. Саме тому ін'єкція неможлива.

    Повертає порожній рядок, якщо команда не знайдена, впала або зависла:
    інвентаризація не повинна ламатись через одну недоступну утиліту.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,   # перехопити stdout і stderr
            text=True,             # віддати рядки, а не байти
            timeout=COMMAND_TIMEOUT,
            check=False,           # ненульовий код виходу не кидає виняток
            encoding="utf-8",
            errors="replace",      # некоректні байти замінити, а не впасти
        )
    except FileNotFoundError:
        # Такої програми в системі немає (напр. dpkg-query на Fedora).
        return ""
    except subprocess.TimeoutExpired:
        print(f"  Команда {command[0]} перевищила таймаут", file=sys.stderr)
        return ""

    return result.stdout


def get_windows_apps() -> list[dict]:
    """
    Windows: читає з реєстру список встановлених програм разом з версіями.

    Дивимось у ДВІ гілки реєстру:
      HKLM\\...\\Uninstall            — 64-бітні програми
      HKLM\\...\\Wow6432Node\\...     — 32-бітні програми на 64-бітній системі
    Багато скриптів забувають про другу і "втрачають" половину інвентаря.

    ConvertTo-Json на боці PowerShell зручніший за розбір тексту:
    JSON має чітку структуру, а текстовий вивід доводиться парсити регулярками.
    """
    powershell_script = (
        "Get-ItemProperty "
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Where-Object { $_.DisplayName } "
        "| Select-Object DisplayName, DisplayVersion, Publisher "
        "| ConvertTo-Json -Compress"
    )

    # -NoProfile — не завантажувати профіль користувача (швидше і передбачуваніше).
    # -NonInteractive — не ставити запитань, якщо щось піде не так.
    output = run_command([
        "powershell", "-NoProfile", "-NonInteractive", "-Command", powershell_script,
    ])

    if not output.strip():
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print("  Не вдалось розібрати вивід PowerShell", file=sys.stderr)
        return []

    # Якщо знайдено рівно одну програму, ConvertTo-Json віддасть об'єкт,
    # а не масив. Це відома пастка PowerShell — обробляємо обидва випадки.
    if isinstance(data, dict):
        data = [data]

    apps = []
    for item in data:
        apps.append({
            "name": item.get("DisplayName", "").strip(),
            "version": (item.get("DisplayVersion") or "").strip(),
            "vendor": (item.get("Publisher") or "").strip(),
        })

    return apps


def get_macos_apps() -> list[dict]:
    """
    macOS: читає версії напряму з Info.plist кожного застосунку.

    Кожен .app на macOS — це насправді тека зі структурою всередині.
    Метадані лежать у Contents/Info.plist у бінарному форматі,
    який стандартний модуль plistlib читає без жодних зовнішніх команд.

    Це швидше і надійніше, ніж `system_profiler SPApplicationsDataType`,
    який на реальній машині може виконуватись 30-60 секунд.
    """
    apps = []

    # Дивимось у три типові розташування:
    #   /Applications                  — програми для всіх користувачів
    #   ~/Applications                 — програми конкретного користувача
    #   /System/Applications           — вбудовані програми Apple
    search_paths = [
        Path("/Applications"),
        Path.home() / "Applications",
        Path("/System/Applications"),
    ]

    # Лічильник пропущених — щоб чесно показати користувачу, що інвентар неповний.
    skipped = 0

    for base in search_paths:
        if not base.exists():
            continue

        # glob("*.app") бере застосунки на верхньому рівні,
        # glob("*/*.app") — ті, що лежать у підтеках (напр. /Applications/Utilities).
        # Сам обхід теки теж може впасти: macOS захищає частину каталогів
        # через TCC, і тоді ми отримаємо PermissionError ще до читання файлів.
        try:
            app_paths = list(base.glob("*.app")) + list(base.glob("*/*.app"))
        except OSError as err:
            print(f"  Не вдалось прочитати {base}: {err}")
            continue

        for app_path in app_paths:
            plist_path = app_path / "Contents" / "Info.plist"

            if not plist_path.exists():
                continue

            try:
                # "rb" — читаємо у двійковому режимі: plist часто бінарний.
                with open(plist_path, "rb") as f:
                    info = plistlib.load(f)
            except Exception:  # noqa: BLE001 — навмисно широко, пояснення нижче
                # ЧОМУ ТУТ ШИРОКИЙ except, хоча зазвичай так робити не варто.
                #
                # plistlib під капотом викликає XML-парсер expat, який піднімає
                # xml.parsers.expat.ExpatError. Цей клас успадковується напряму
                # від Exception — тобто НЕ є ані OSError, ані ValueError,
                # і перелік конкретних типів помилок його не спіймає.
                # Крім нього тут можливі помилки прав доступу, обірвані симлінки,
                # нестандартні формати від сторонніх розробників.
                #
                # Правило таке: широкий except виправданий, коли ви в циклі
                # обробляєте сотні ЧУЖИХ файлів і одна погана штука не повинна
                # зупиняти всю роботу. Він НЕ виправданий у бізнес-логіці,
                # де помилка означає, що далі рахувати немає сенсу.
                skipped += 1
                continue

            # plist може містити не словник, а масив або рядок.
            # Тоді .get() не існує і ми впадемо вже на наступному рядку.
            if not isinstance(info, dict):
                skipped += 1
                continue

            apps.append({
                # CFBundleShortVersionString — це версія "для людей" (напр. 141.0.1).
                # CFBundleVersion — внутрішній номер збірки, для CVE він гірший.
                "name": str(info.get("CFBundleName") or app_path.stem),
                "version": str(info.get("CFBundleShortVersionString", "")),
                "vendor": str(info.get("CFBundleIdentifier", "")),
            })

    if skipped:
        print(f"  Пропущено застосунків з нечитабельним Info.plist: {skipped}")

    return apps


def get_linux_apps() -> list[dict]:
    """
    Linux: пробує пакетні менеджери по черзі — dpkg, потім rpm, потім pacman.

    Формат виводу задаємо самі, щоб не парсити "красиві" таблиці:
    роздільник \\t (табуляція) зустрічається в назвах пакетів набагато рідше,
    ніж пробіл, тому розбір виходить надійним.
    """
    # (команда, чи є вендор у виводі)
    candidates = [
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],           # Debian/Ubuntu
        ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],    # Fedora/RHEL
        ["pacman", "-Q"],                                              # Arch (роздільник — пробіл)
    ]

    for command in candidates:
        output = run_command(command)
        if not output.strip():
            continue

        apps = []
        for line in output.strip().split("\n"):
            # pacman розділяє пробілом, решта — табуляцією.
            parts = line.split("\t") if "\t" in line else line.split(" ", 1)

            if not parts or not parts[0]:
                continue

            apps.append({
                "name": parts[0].strip(),
                "version": parts[1].strip() if len(parts) > 1 else "",
                "vendor": "",
            })

        if apps:
            return apps

    return []


def collect_inventory() -> list[dict]:
    """Визначає ОС і викликає відповідний збирач."""
    system = platform.system()

    if system == "Windows":
        return get_windows_apps()
    if system == "Darwin":  # так macOS називається всередині системи
        return get_macos_apps()
    if system == "Linux":
        return get_linux_apps()

    raise OSError(f"Непідтримувана ОС: {system}")


def deduplicate(apps: list[dict]) -> list[dict]:
    """
    Прибирає дублікати за парою (назва, версія) і сортує за назвою.

    Один застосунок може трапитись двічі: наприклад, і в /Applications,
    і в ~/Applications. Ключем робимо саме пару, а не лише назву, —
    інакше загубимо дві різні встановлені версії однієї програми,
    а це якраз те, що цікавить нас найбільше.
    """
    seen = {}

    for app in apps:
        if not app["name"]:
            continue
        key = (app["name"].lower(), app["version"])
        seen.setdefault(key, app)

    return sorted(seen.values(), key=lambda a: a["name"].lower())


def main() -> int:
    parser = argparse.ArgumentParser(description="Інвентаризація встановленого ПЗ")
    parser.add_argument("--out", default="inventory.json", help="файл для збереження")
    parser.add_argument("--limit", type=int, default=20, help="скільки показати на екрані")
    args = parser.parse_args()

    print(f"ОС: {platform.system()} {platform.release()} ({platform.machine()})")
    print("Збираю інвентар...\n")

    try:
        apps = deduplicate(collect_inventory())
    except OSError as err:
        print(f"Помилка: {err}", file=sys.stderr)
        return 1

    if not apps:
        print("Нічого не знайдено. Можливо, потрібні інші права або інший пакетний менеджер.")
        return 1

    print(f"Знайдено програм: {len(apps)}\n")

    # Скільки з них взагалі мають версію — це показник якості інвентаря.
    with_version = sum(1 for a in apps if a["version"])
    print(f"З версією: {with_version} ({with_version / len(apps) * 100:.0f}%)\n")

    # Виводимо перші N у вигляді таблиці.
    # {i:>3} — вирівняти число по правому краю в полі шириною 3
    # {name:<45} — вирівняти текст по лівому краю в полі шириною 45
    for i, app in enumerate(apps[:args.limit], start=1):
        name = app["name"][:44]
        version = app["version"] or "—"
        print(f"{i:>3}. {name:<45} {version}")

    if len(apps) > args.limit:
        print(f"\n... та ще {len(apps) - args.limit}")

    # Зберігаємо у JSON.
    # ensure_ascii=False — щоб кирилиця збереглась як текст, а не як \u0430\u0431.
    # indent=2 — щоб файл можна було читати очима і дивитись у git diff.
    output_path = Path(args.out)
    output_path.write_text(
        json.dumps(apps, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"\nІнвентар збережено у {output_path.resolve()}")
    print("Далі: подайте цей файл у 06_risk_report.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3

import csv  # noqa: F401
import os
import time  # noqa: F401
import requests  # noqa: F401
import json  # noqa: F401
from pathlib import Path
from dotenv import load_dotenv  
load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "CyberCourse-Lesson11/1.0"
MY_APPS = [
    {"name": "Copilot", "version": "150.0.4078.96"},
    {"name": "Google Chrome", "version": "151.0.7922.138"},
    {"name": "Maple 17", "version": "17.0.0.0"},
    {"name": "Steam", "version": "2.10.91.91"},
    {"name": "Zoom Workplace (64-bit)", "version": "7.0.34412"},
]

def get_delay() -> float:
    """Пауза між запитами до NVD: 6 с без ключа, 0.6 с з ключем."""
    return 0.6 if os.environ.get("NVD_API_KEY") else 6.0


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
def search_nvd(app_name: str, limit: int = 3) -> list[dict]:
    params = {"keywordSearch": app_name, "resultsPerPage": str(limit)}
    headers = {"User-Agent": USER_AGENT}
    
    if api_key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = api_key

    try:
        res = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
        res.raise_for_status()
        data = res.json()
    except requests.exceptions.RequestException as err:
        print(f"Помилка NVD ({app_name}): {err}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        
        
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        
        score, severity = None, "UNKNOWN"
        for ver in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            if ver in metrics and metrics[ver]:
                metric_item = metrics[ver][0]
                cvss_data = metric_item.get("cvssData", {})
                
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or metric_item.get("baseSeverity", "UNKNOWN")
                break

        results.append({
            "cve_id": cve.get("id", ""),
            "vuln_status": cve.get("vulnStatus", "UNKNOWN"),
            "cvss": score,
            "severity": severity,
            "description": description,
        }) 
    return results



"""
     TODO 2: завантажити каталог KEV і повернути множину CVE ID.

    Кроки:
    1. requests.get(KEV_URL, timeout=60)
    2. Дістати список за ключем "vulnerabilities"
    3. Зібрати множину значень "cveID"

     Бонус (+0 балів, але правильно): зберегти файл на диск і не качати
     його повторно, якщо він свіжіший за добу.
"""

def load_kev() -> set[str]:
    
    cache_file = Path("kev_cache.json")
    
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime < 86400):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None
    else:
        data = None

    if not data:
        try:
            res = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=60)
            res.raise_for_status()
            data = res.json()
            
            cache_file.write_text(res.text, encoding="utf-8")
        except requests.exceptions.RequestException as err:
            print(f"Помилка завантаження KEV: {err}")
            return set()

    vulnerabilities = data.get("vulnerabilities", [])
    return {item["cveID"] for item in vulnerabilities if "cveID" in item}


"""
     TODO 3: отримати EPSS-оцінки для списку CVE.

     Кроки:
       1. Об'єднати ID через кому: ",".join(cve_ids)
       2. requests.get(EPSS_URL, params={"cve": ...})
       3. З відповіді взяти список "data"
       4. Повернути {item["cve"]: float(item["epss"])}
   
       Увага: API повертає числа РЯДКАМИ. Без float() порівняння працюватиме дивно.
     """

def load_epss(cve_ids: list[str]) -> dict[str, float]:
    
    if not cve_ids:
        return {}

    cve_param = ",".join(cve_ids)

    try:
        res = requests.get(
            EPSS_URL,
            params={"cve": cve_param},
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        res.raise_for_status()
        json_data = res.json()
    except requests.exceptions.RequestException as err:
        print(f"Помилка завантаження EPSS: {err}")
        return {}

    data_list = json_data.get("data", [])
    return {item["cve"]: float(item["epss"]) for item in data_list}


"""
     TODO 4: реалізувати правила пріоритезації.

         KEV                        -> "P1"
         EPSS >= 0.5                -> "P2"
         EPSS >= 0.1                -> "P3"
         CVSS >= 9.0                -> "P3"
         інакше                     -> "P4"

     Порядок перевірок важливий. Подумайте, чому KEV перевіряється першим.
     """
     
def get_priority(in_kev: bool, epss: float, cvss: float | None) -> str:
    if in_kev:
        return "P1"

    if epss >= 0.5:
        return "P2"

    if epss >= 0.1 or (cvss is not None and cvss >= 9.0):
        return "P3"

    return "P4"


"""
     TODO 5: зберегти результат у CSV.

     Колонки: app, installed_version, cve_id, cvss, severity, in_kev, epss, priority

     Не забудьте: newline="" та encoding="utf-8-sig".
     """

def save_csv(rows: list[dict], filename: str) -> None:
    fieldnames = [
        "app",
        "installed_version",
        "cve_id",
        "cvss",
        "severity",
        "in_kev",
        "epss",
        "priority",
    ]

    try:
        with open(filename, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in rows:
                filtered_row = {key: row.get(key, "") for key in fieldnames}
                writer.writerow(filtered_row)
                
        print(f"Звіт успішно збережено у файл: {filename}")
    except Exception as err:
        print(f"Помилка при збереженні CSV: {err}")

# TODO 6: викликати search_nvd(), додати результати до all_rows
# TODO 7: не забути про паузу time.sleep(get_delay()) між запитами
# TODO 8: завантажити KEV, отримати EPSS, проставити пріоритети
# TODO 9: викликати save_csv() і вивести підсумок по P1/P2/P3/P4


def main() -> None:
    print("Домашнє завдання: звіт про ризики\n")

    inventory_file = "inventory.json"
    if os.path.exists(inventory_file):
        with open(inventory_file, "r", encoding="utf-8") as f:
            apps = json.load(f)
    else:
        apps = MY_APPS

    all_rows: list[dict] = []

    for i, app in enumerate(apps, start=1):
        app_name = app.get("name", "")
        app_version = app.get("version", "")
        print(f"[{i}/{len(apps)}] {app_name} {app_version}")

        cves = search_nvd(app_name, limit=3)

        for cve in cves:
            all_rows.append({
                "app": app_name,
                "installed_version": app_version,
                "cve_id": cve["cve_id"],
                "cvss": cve["cvss"],
                "severity": cve["severity"],
                "description": cve.get("description", ""),
            })

        if i < len(apps):
            time.sleep(get_delay())

    if not all_rows:
        print("\nВразливостей не знайдено або сталася помилка.")
        return

    print("\n[+] Завантаження каталогу CISA KEV...")
    kev_ids = load_kev()

    print("[+] Отримання оцінок EPSS...")
    all_cve_ids = [row["cve_id"] for row in all_rows if row["cve_id"]]
    epss_map = load_epss(all_cve_ids)

    priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}

    for row in all_rows:
        cve_id = row["cve_id"]
        in_kev = cve_id in kev_ids
        epss_score = epss_map.get(cve_id, 0.0)

        priority = get_priority(in_kev=in_kev, epss=epss_score, cvss=row["cvss"])

        row["in_kev"] = in_kev
        row["epss"] = epss_score
        row["priority"] = priority

        priority_counts[priority] += 1

    output_filename = "homework_risk_report.csv"
    save_csv(all_rows, output_filename)

    print(f"\nЗібрано рядків: {len(all_rows)}")
    print("Статистика за пріоритетами:")
    for p_level, count in priority_counts.items():
        print(f"  {p_level}: {count}")


if __name__ == "__main__":
    main()

# language: python
# -*- coding: utf-8 -*-

"""
Утилита SNMP walk с многоуровневым гибридным анализом. (Версия 9.14)

Эта версия добавляет третий уровень анализа:
1. Идентификация вендора устройства.
2. Точный поиск по стандартным OID (высший приоритет).
3. Точный поиск по OID特定ного вендора (второй приоритет).
4. "Умный" поиск по ключевым словам для заполнения пробелов (низший приоритет).

Как использовать:
1. pip install pysnmp openpyxl
2. python snmp_walk_tool.py <IP-адрес> -o results.xlsx

openpyxl           3.1.5
pyasn1             0.6.0
pysmi-lextudio     1.4.3
pysnmp             5.1.0

"""

import sys
import asyncio
import argparse
import logging
from collections import defaultdict

try:
    from pysnmp.hlapi.asyncio import *
    from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
    from pysnmp.proto import rfc1905
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

# --- Конфигурация SNMP ---
SNMP_COMMUNITY = 'public'
SNMP_TIMEOUT = 2
SNMP_RETRIES = 1
OID_TO_WALK = '1.3.6.1.2.1'

# --- БАЗА ЗНАНИЙ OID ---

# 1. СТАНДАРТНЫЕ OID (ВЫСШИЙ ПРИОРИТЕТ)
PRECISE_OIDS = {
    '1.3.6.1.2.1.1.1.0': 'Device Description',
    '1.3.6.1.2.1.1.5.0': 'Device Name (sysName)',
    '1.3.6.1.2.1.43.5.1.1.17.1': 'Serial Number',
    '1.3.6.1.2.1.43.10.2.1.4.1.1': 'Total Page Count',
    '1.3.6.1.2.1.25.3.2.1.5.1': 'Printer Status',
    '1.3.6.1.2.1.43.11.1.1.9': 'Toner Remaining Level', # Таблица
    '1.3.6.1.2.1.43.12.1.1.5': 'Drum Unit Remaining Level', # Таблица
    
}

# 2. OID КОНКРЕТНЫХ ВЕНДОРОВ (ВТОРОЙ ПРИОРИТЕТ)
VENDOR_OIDS = {
    'kyocera': {
        '1.3.6.1.4.1.1347.42.3.1.1.1.4.1': 'Toner Remaining Level (Black) - Kyocera',
        '1.3.6.1.4.1.1347.42.3.1.1.1.4.2': 'Toner Remaining Level (Cyan) - Kyocera',
        '1.3.6.1.4.1.1347.42.3.1.1.1.4.3': 'Toner Remaining Level (Magenta) - Kyocera',
        '1.3.6.1.4.1.1347.42.3.1.1.1.4.4': 'Toner Remaining Level (Yellow) - Kyocera',
        '1.3.6.1.2.1.25.3.2.1.3.1': 'Device Name (sysName) - Kyocera',
        '1.3.6.1.2.1.43.11.1.1.9.1.1': 'Toner Remaining Level (Black) - Kyocera',
    },
    'hp': {
        '1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.2.7': 'Maintenance Kit Max Capacity - HP',
        '1.3.6.1.4.1.11.2.3.9.4.2.1.4.1.3.7': 'Maintenance Kit Remaining Level - HP',
    },
    # Добавляйте других вендоров сюда...
    'canon': {},
    'ricoh': {},
}

# 3. КРИТЕРИИ ДЛЯ УМНОГО ПОИСКА (НИЗШИЙ ПРИОРИТЕТ)
KEYWORD_SEARCH_CRITERIA = {
    'Device Description': [['model'], ['descr']],
    'Serial Number': [['serial']],
    'Total Page Count': [['page', 'count'], ['counter', 'total']],
    'Printer Status': [['status'], ['state']],
    'Alert Message on Display': [['alert'], ['display']],
    'Toner Remaining Level (Black)': [['black', 'level'], ['black', 'remaining']],
}

logger = logging.getLogger(__name__)

def identify_vendor(full_results):
    """Определяет вендора по значению sysDescr."""
    sys_descr_oid = '1.3.6.1.2.1.1.1.0'
    for num_oid, _, value in full_results:
        if num_oid == sys_descr_oid:
            val_lower = value.lower()
            for vendor in VENDOR_OIDS:
                if vendor in val_lower:
                    logger.info(f"Идентифицирован вендор: {vendor.capitalize()}")
                    return vendor
    logger.info("Не удалось идентифицировать вендора по sysDescr.")
    return None

def analyze_results(full_results):
    """Выполняет трехуровневый гибридный анализ."""
    monitoring_data = {}
    found_base_descriptions = set()
    param_counts = defaultdict(int)

    # --- Фаза 1: Идентификация вендора ---
    identified_vendor = identify_vendor(full_results)

    # --- Фаза 2: Точный поиск (Стандартные + Вендорские OID) ---
    logger.info("Выполняю точный поиск по стандартным и вендорским OID...")
    
    # Объединяем OID в один список с правильным приоритетом
    search_oids = list(PRECISE_OIDS.items())
    if identified_vendor and identified_vendor in VENDOR_OIDS:
        search_oids.extend(list(VENDOR_OIDS[identified_vendor].items()))
    
    for numeric_oid, _, value in full_results:
        for precise_oid_base, description in search_oids:
            if numeric_oid.startswith(precise_oid_base):
                # Проверяем, не был ли параметр с таким *базовым* именем уже найден
                # Это дает приоритет стандартным OID, т.к. они в списке раньше
                if description in found_base_descriptions:
                    continue
                
                param_counts[description] += 1
                final_description = f"{description} ({param_counts[description]})" if param_counts[description] > 1 else description
                
                monitoring_data[final_description] = [numeric_oid, value]
                # Добавляем базовое имя в список найденных, чтобы не искать его снова
                if param_counts[description] == 1:
                     found_base_descriptions.add(description)

    # --- Фаза 3: Умный поиск по ключевым словам для оставшихся ---
    logger.info("Выполняю эвристический поиск по ключевым словам для оставшихся параметров...")
    for parameter_name, keyword_sets in KEYWORD_SEARCH_CRITERIA.items():
        if parameter_name in found_base_descriptions:
            continue

        for numeric_oid, symbolic_oid, value in full_results:
            search_string = (symbolic_oid + ' ' + value).lower()
            if parameter_name in monitoring_data: break
            
            for keyword_set in keyword_sets:
                if all(keyword in search_string for keyword in keyword_set):
                    monitoring_data[parameter_name] = [numeric_oid, value]
                    break
    
    logger.info(f"Анализ завершен. Найдено {len(monitoring_data)} ключевых параметров.")
    return monitoring_data

def save_to_excel(filename, full_data, important_data):
    """Сохраняет два набора данных в разные листы одного Excel-файла."""
    # (Эта функция осталась без изменений)
    if not OPENPYXL_AVAILABLE: logger.error("Библиотека 'openpyxl' не установлена."); return
    logger.info(f"\nСохраняю результаты в файл '{filename}'...")
    try:
        workbook = openpyxl.Workbook()
        ws1 = workbook.active; ws1.title = "Full SNMP Walk"
        ws1.append(['Numeric OID', 'Symbolic OID', 'Value'])
        for row in full_data: ws1.append(row)
        for column_cells in ws1.columns:
            length = max(len(str(cell.value)) for cell in column_cells)
            ws1.column_dimensions[column_cells[0].column_letter].width = length + 2
        if important_data:
            ws2 = workbook.create_sheet(title="Monitoring Info")
            ws2.append(['Parameter', 'Found OID', 'Value'])
            for param, data in important_data.items(): ws2.append([param, data[0], data[1]])
            for column_cells in ws2.columns:
                length = max(len(str(cell.value)) for cell in column_cells)
                ws2.column_dimensions[column_cells[0].column_letter].width = length + 2
        workbook.save(filename)
        logger.info(f"Успешно сохранено в '{filename}'")
    except Exception as e:
        logger.error(f"Не удалось сохранить Excel-файл: {e}")

async def perform_snmp_walk(target_ip: str, community: str, start_oid_str: str):
    # (Эта функция осталась без изменений)
    logger.info(f"--- Начинаю SNMP walk для IP: {target_ip} ---")
    snmp_engine = SnmpEngine()
    total_oids_found = 0
    results_for_analysis = []
    current_oid_for_request = ObjectIdentity(start_oid_str) 
    try:
        boundary_tuple = tuple(int(x) for x in start_oid_str.split('.'))
    except ValueError:
        logger.critical(f"Неверный формат OID: {start_oid_str}"); return None
    while True:
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            snmp_engine, CommunityData(community),
            UdpTransportTarget((target_ip, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES),
            ContextData(), ObjectType(current_oid_for_request)
        )
        if errorIndication or errorStatus or not varBinds or not varBinds[0]: break
        var_bind_element = varBinds[0][0]
        try: oid_object, value_object = var_bind_element
        except (ValueError, TypeError): break
        oid_tuple = oid_object.getOid()
        if len(oid_tuple) < len(boundary_tuple) or oid_tuple[:len(boundary_tuple)] != boundary_tuple: break
        if value_object.isSameTypeWith(rfc1905.EndOfMibView()): break
        total_oids_found += 1
        oid_symbolic = oid_object.prettyPrint(); value_str = value_object.prettyPrint()
        logger.info(f"{oid_symbolic} = {value_str}")
        oid_str_numeric = ".".join(map(str, oid_tuple))
        results_for_analysis.append([oid_str_numeric, oid_symbolic, value_str])
        current_oid_for_request = oid_object
    logger.info(f"\n--- SNMP walk завершен. Всего найдено OID: {total_oids_found} ---")
    return results_for_analysis

async def main():
    parser = argparse.ArgumentParser(description="Утилита SNMP walk с гибридным анализом.")
    parser.add_argument("ip_address", help="IP-адрес целевого устройства.")
    parser.add_argument("--output", "-o", help="Имя Excel-файла для сохранения результатов.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[logging.StreamHandler(sys.stdout)])
    if not PYSNMP_AVAILABLE: logger.critical("Ошибка: библиотека pysnmp не найдена."); sys.exit(1)
    try:
        results = await perform_snmp_walk(args.ip_address, SNMP_COMMUNITY, OID_TO_WALK)
        if args.output and results:
            analyzed_results = analyze_results(results)
            save_to_excel(args.output, results, analyzed_results)
    except Exception as e:
        logger.exception(f"\nПроизошла непредвиденная ошибка: {e}")

if __name__ == "__main__":
    asyncio.run(main())

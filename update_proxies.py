import asyncio
import aiohttp
import json
import re
import time
import logging
from typing import Optional

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- КОНФИГУРАЦИЯ ---
TIMEOUT_SECONDS = 2.0
TOP_N_PROXIES = 50
OUTPUT_FILE = "proxies.json"

# Резервный список MTProto прокси (на случай недоступности внешних источников)
FALLBACK_PROXIES = [
    "142.250.185.46:443:ee1234567890abcdef1234567890abcdef",
    "185.76.151.11:8888:dd000000000000000000000000000000",
    "51.159.111.59:443:bb111111111111111111111111111111",
    "95.217.144.108:8443:aa222222222222222222222222222222",
    "176.9.44.150:443:cc333333333333333333333333333333"
]

# Источники данных (сырые ссылки на GitHub или другие открытые репозитории)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/Proxy4All/Proxy-List/main/mtproto.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"
]

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def get_flag_emoji(country_code: str) -> str:
    """Преобразует ISO-код страны (например, 'DE') в Emoji-флаг."""
    if not country_code or len(country_code) != 2:
        return "🏳️"
    try:
        return chr(ord(country_code[0].upper()) + 127397) + chr(ord(country_code[1].upper()) + 127397)
    except Exception:
        return "🏳️"

def parse_proxy_line(line: str) -> Optional[dict]:
    """Парсит строку и возвращает словарь прокси или None."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Формат Telegram-ссылки: t.me/proxy?server=...&port=...&secret=...
    tg_match = re.search(r'server=([^&]+)&port=(\d+)&secret=([a-zA-Z0-9]+)', line)
    if tg_match:
        return {"protocol": "MTProto", "ip": tg_match.group(1), "port": int(tg_match.group(2)), "secret": tg_match.group(3)}

    # Формат IP:PORT:SECRET (MTProto)
    mtproto_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5}):([a-zA-Z0-9]{16,})$', line)
    if mtproto_match:
        return {"protocol": "MTProto", "ip": mtproto_match.group(1), "port": int(mtproto_match.group(2)), "secret": mtproto_match.group(3)}

    # Формат IP:PORT (SOCKS5)
    socks_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$', line)
    if socks_match:
        return {"protocol": "SOCKS5", "ip": socks_match.group(1), "port": int(socks_match.group(2)), "secret": None}

    return None

# --- ОСНОВНАЯ ЛОГИКА ---

async def fetch_sources(session: aiohttp.ClientSession) -> list[dict]:
    """Скачивает и парсит прокси из всех источников."""
    raw_lines = list(FALLBACK_PROXIES)
    
    tasks = []
    for url in PROXY_SOURCES:
        tasks.append(fetch_url(session, url))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for res in results:
        if isinstance(res, str):
            raw_lines.extend(res.splitlines())

    proxies = []
    seen = set()
    for line in raw_lines:
        parsed = parse_proxy_line(line)
        if parsed:
            unique_key = f"{parsed['ip']}:{parsed['port']}"
            if unique_key not in seen:
                seen.add(unique_key)
                proxies.append(parsed)
    
    logging.info(f"Собрано уникальных прокси для проверки: {len(proxies)}")
    return proxies

async def fetch_url(session: aiohttp.ClientSession, url: str) -> str:
    """Асинхронно получает текст по URL."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                return await response.text()
    except Exception as e:
        logging.warning(f"Ошибка при загрузке {url}: {e}")
    return ""

async def check_ping(proxy: dict) -> Optional[dict]:
    """Проверяет доступность прокси и замеряет пинг через TCP-сокет."""
    start_time = time.perf_counter()
    try:
        # Используем asyncio.open_connection для быстрого TCP-чека
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy["ip"], proxy["port"]),
            timeout=TIMEOUT_SECONDS
        )
        writer.close()
        await writer.wait_closed()
        
        ping_ms = round((time.perf_counter() - start_time) * 1000)
        proxy["ping"] = ping_ms
        proxy["status"] = "online"
        return proxy
    except Exception:
        return None

async def get_geolocation(session: aiohttp.ClientSession, ips: list[str]) -> dict:
    """Получает геолокацию для списка IP через batch-запрос (экономит лимиты)."""
    url = "http://ip-api.com/batch"
    payload = [{"query": ip} for ip in ips]
    
    try:
        async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status == 200:
                data = await response.json()
                # Преобразуем список ответов в словарь для быстрого доступа
                return {item["query"]: item for item in data if item.get("status") == "success"}
    except Exception as e:
        logging.error(f"Ошибка при запросе геолокации: {e}")
    return {}

async def main():
    logging.info("Запуск сборщика прокси...")
    async with aiohttp.ClientSession() as session:
        # 1. Сбор и парсинг
        proxies = await fetch_sources(session)
        if not proxies:
            logging.error("Не удалось получить ни одного прокси из источников.")
            return

        # 2. Проверка пинга (параллельно)
        logging.info("Проверка доступности и замера пинга...")
        tasks = [check_ping(p) for p in proxies]
        checked_proxies = await asyncio.gather(*tasks)
        
        # Фильтруем только успешные (online)
        online_proxies = [p for p in checked_proxies if p is not None]
        logging.info(f"Успешно проверено: {len(online_proxies)} прокси.")

        if not online_proxies:
            logging.error("Ни один прокси не прошел проверку.")
            return

        # 3. Геолокация (только для уникальных IP успешных прокси)
        unique_ips = list(set(p["ip"] for p in online_proxies))
        logging.info(f"Запрос геолокации для {len(unique_ips)} уникальных IP...")
        geo_data = await get_geolocation(session, unique_ips)

        # 4. Обогащение данных, сортировка и выборка ТОП-50
        final_proxies = []
        for p in online_proxies:
            ip_info = geo_data.get(p["ip"], {})
            country = ip_info.get("country", "Unknown")
            country_code = ip_info.get("countryCode", "XX")
            
            final_proxies.append({
                "protocol": p["protocol"],
                "country": country,
                "flag": get_flag_emoji(country_code),
                "ip": p["ip"],
                "port": p["port"],
                "ping": p["ping"],
                "secret": p["secret"],
                "status": "online"
            })

        # Сортировка по пингу (возрастание) и выборка ТОП-50
        final_proxies.sort(key=lambda x: x["ping"])
        top_proxies = final_proxies[:TOP_N_PROXIES]

        # Добавляем ID (1, 2, 3...)
        for idx, proxy in enumerate(top_proxies, start=1):
            proxy["id"] = idx

        # 5. Сохранение в файл
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(top_proxies, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Готово! Сохранено ТОП-{len(top_proxies)} прокси в {OUTPUT_FILE}")

if __name__ == "__main__":
    # Для Windows требуется установка политики цикла событий, если используется asyncio
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())

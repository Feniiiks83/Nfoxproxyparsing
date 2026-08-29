import asyncio
import aiohttp
import json
import re
import time
import logging
import datetime
from typing import Optional, List, Dict
from urllib.parse import urlparse, parse_qs

# --- НАСТРОЙКИ ---
TIMEOUT_SECONDS = 2.0
TOP_N_PROXIES = 50
OUTPUT_FILE = "proxies.json"
MAX_CONCURRENT_CHECKS = 100  # Ограничение потоков для предотвращения "Too many open files"

# Синтаксически валидные резервные прокси (будут отсеяны сетевой проверкой, если оффлайн)
FALLBACK_PROXIES = [
    "142.250.185.46:443:ee1234567890abcdef1234567890abcdef",
    "185.76.151.11:8888:dd000000000000000000000000000000",
    "51.159.111.59:443:eeabcdef1234567890abcdef12345678"
]

# Надежные и регулярно обновляемые публичные источники
PROXY_SOURCES = [
    # MTProto
    "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/mtproto.txt",
    "https://raw.githubusercontent.com/Grim1313/mtproto-for-telegram/main/all_proxies.txt",
    # SOCKS5 & Telegram
    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/telegramProxys.txt",
    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks5.txt",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/main/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/socks5/raw/all.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
def get_flag_emoji(country_code: str) -> str:
    """Преобразует ISO-код страны в Emoji-флаг."""
    if not country_code or len(country_code) != 2:
        return "🏳️"
    try:
        return chr(ord(country_code[0].upper()) + 127397) + chr(ord(country_code[1].upper()) + 127397)
    except Exception:
        return "🏳️"

def parse_proxy_line(line: str) -> Optional[Dict]:
    """Гибкий парсинг прокси из строки."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # 1. Парсинг URL-формата (tg:// или https://t.me/proxy)
    if line.startswith('tg://') or 't.me/proxy' in line:
        try:
            parsed_url = urlparse(line)
            query_params = parse_qs(parsed_url.query)
            server = query_params.get('server', [None])[0]
            port_str = query_params.get('port', [None])[0]
            secret = query_params.get('secret', [None])[0]
            if server and port_str and secret:
                return {
                    "protocol": "MTProto",
                    "ip": server,
                    "port": int(port_str),
                    "secret": secret
                }
        except (ValueError, TypeError):
            pass 

    # 2. Парсинг формата IP:PORT:SECRET (MTProto)
    mtproto_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5}):((?:ee|dd)?[a-fA-F0-9]{32,64})$', line)
    if mtproto_match:
        return {
            "protocol": "MTProto",
            "ip": mtproto_match.group(1),
            "port": int(mtproto_match.group(2)),
            "secret": mtproto_match.group(3)
        }

    # 3. Парсинг формата IP:PORT (SOCKS5)
    socks_match = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})$', line)
    if socks_match:
        return {
            "protocol": "SOCKS5",
            "ip": socks_match.group(1),
            "port": int(socks_match.group(2)),
            "secret": None
        }

    return None

# --- ЛОГИКА ПРОВЕРКИ ---
async def check_socks5(proxy: dict, semaphore: asyncio.Semaphore) -> Optional[dict]:
    """Реальная валидация SOCKS5 через отправку байт рукопожатия."""
    async with semaphore:
        try:
            start_time = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy["ip"], proxy["port"]),
                timeout=TIMEOUT_SECONDS
            )
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            response = await asyncio.wait_for(reader.readexactly(2), timeout=TIMEOUT_SECONDS)
            writer.close()
            await writer.wait_closed()
            
            if response == b'\x05\x00':
                proxy["ping"] = round((time.perf_counter() - start_time) * 1000)
                proxy["status"] = "online"
                return proxy
        except Exception:
            pass
    return None

async def check_mtproto(proxy: dict, semaphore: asyncio.Semaphore) -> Optional[dict]:
    """Валидация MTProto: строгая проверка секрета + базовое TCP-подключение."""
    secret = proxy.get("secret", "")
    if not re.match(r'^(?:ee|dd)?[a-fA-F0-9]{32,64}$', secret):
        return None

    async with semaphore:
        try:
            start_time = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy["ip"], proxy["port"]),
                timeout=TIMEOUT_SECONDS
            )
            writer.close()
            await writer.wait_closed()
            
            proxy["ping"] = round((time.perf_counter() - start_time) * 1000)
            proxy["status"] = "online"
            return proxy
        except Exception:
            return None

async def fetch_sources(session: aiohttp.ClientSession) -> List[Dict]:
    """Скачивает и объединяет данные из всех источников."""
    raw_lines = list(FALLBACK_PROXIES)
    tasks = [fetch_url(session, url) for url in PROXY_SOURCES]
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

async def get_geolocation_batched(session: aiohttp.ClientSession, ips: List[str]) -> Dict:
    """Пакетный запрос геолокации чанками строго по 100 IP."""
    geo_data = {}
    chunk_size = 100
    
    for i in range(0, len(ips), chunk_size):
        chunk = ips[i:i + chunk_size]
        payload = [{"query": ip} for ip in chunk]
        try:
            async with session.post("http://ip-api.com/batch", json=payload, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data:
                        if item.get("status") == "success":
                            geo_data[item["query"]] = item
                elif response.status == 429:
                    logging.warning("Превышен лимит GeoIP API. Ждем 60 секунд...")
                    await asyncio.sleep(60)
                    # Можно повторить запрос, но для простоты просто идем дальше
        except Exception as e:
            logging.warning(f"Ошибка GeoIP batch запроса: {e}")
            
        # Задержка 4 секунды (бесплатный лимит ip-api.com: 15 запросов в минуту = 1 запрос в 4 сек)
        if i + chunk_size < len(ips):
            await asyncio.sleep(4) 
            
    return geo_data

# --- ОСНОВНОЙ ЦИКЛ ---
async def main():
    logging.info("🚀 Запуск сборщика прокси...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    
    async with aiohttp.ClientSession() as session:
        # 1. Сбор и парсинг
        proxies = await fetch_sources(session)
        if not proxies:
            logging.error("❌ Не удалось получить ни одного прокси из источников.")
            return handle_fallback()
            
        # 2. Проверка доступности
        logging.info("⏳ Проверка доступности и замера пинга...")
        tasks = []
        for p in proxies:
            if p["protocol"] == "SOCKS5":
                tasks.append(check_socks5(p, semaphore))
            else:
                tasks.append(check_mtproto(p, semaphore))
                
        checked_proxies = await asyncio.gather(*tasks)
        online_proxies = [p for p in checked_proxies if p is not None]
        logging.info(f"✅ Успешно проверено: {len(online_proxies)} прокси.")
        
        # 3. Если ни один прокси не прошел проверку - используем старые данные
        if not online_proxies:
            logging.warning("⚠️ Ни один прокси не прошел проверку. Пытаемся использовать старые данные...")
            return handle_fallback()
            
        # 4. Геолокация
        unique_ips = list(set(p["ip"] for p in online_proxies))
        logging.info(f"🌍 Запрос геолокации для {len(unique_ips)} уникальных IP...")
        geo_data = await get_geolocation_batched(session, unique_ips)
        
        # 5. Обогащение данных, сортировка и выборка ТОП-50
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
            
        final_proxies.sort(key=lambda x: x["ping"])
        top_proxies = final_proxies[:TOP_N_PROXIES]
        
        for idx, proxy in enumerate(top_proxies, start=1):
            proxy["id"] = idx
            
        # 6. Сохранение в файл
        save_proxies(top_proxies)

def save_proxies(proxies_list: list):
    """Сохраняет список прокси в JSON."""
    output_data = {
        "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(proxies_list),
        "proxies": proxies_list
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    logging.info(f"🎉 Готово! Сохранено {len(proxies_list)} прокси в {OUTPUT_FILE}")

def handle_fallback():
    """Обработка сбоев: если новых прокси нет, берем старые или создаем пустой файл."""
    try:
        # Пытаемся прочитать старый файл
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            old_data = json.load(f)
        # Обновляем только время, чтобы фронтенд понимал, что скрипт запускался
        old_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        old_data["is_fallback"] = True # Пометка для фронтенда (опционально)
        
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(old_data, f, indent=2, ensure_ascii=False)
        logging.info("✅ Сбой проверки. Использованы старые данные из proxies.json.")
    except FileNotFoundError:
        # Если старого файла вообще нет (первый запуск), создаем пустой, чтобы сайт не упал
        logging.warning("⚠️ Старый файл не найден. Создаем пустой proxies.json.")
        empty_data = {
            "updated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total": 0,
            "proxies": [],
            "error": "No proxies available at the moment"
        }
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(empty_data, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except Exception as e:
        # Глобальный перехватчик ошибок. Если скрипт упал с критической ошибкой, все равно создаем файл!
        logging.critical(f"💥 Критическая ошибка скрипта: {e}")
        handle_fallback()

import requests
import argparse
from colorama import Fore, init
import aiohttp
import asyncio

init()

API_KEY = "API" # Вставьте ваш API ключ VirusTotal здесь
HEADERS = {"x-apikey": API_KEY}

def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Ошибка запроса: {e}{Fore.RESET}")
        return None

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        return response
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Ошибка запроса: {e}{Fore.RESET}")
        return None

def handle_response(response, ioc_type):
    if response and response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        total = sum(stats.values())

        color = Fore.RED if malicious > 0 else Fore.GREEN
        print(f"\n{color}┌── Результат проверки {ioc_type} ──")
        print(f"├ Зловредность: {malicious}/{total} детекторов")
        print(f"└──────────────────────────────{Fore.RESET}\n")
        return True
    else:
        error_msg = response.json().get('error', {}).get('message', 'Неизвестная ошибка') if response else 'Нет ответа от сервера'
        print(f"{Fore.YELLOW}[!] Ошибка {getattr(response, 'status_code', '')}: {error_msg}{Fore.RESET}")
        return False

async def async_check(ioc, ioc_type):
    """Асинхронная проверка"""
    url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if ioc_type == 'IP' else 'files'}/{ioc}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=HEADERS, timeout=10) as response:
                data = await response.json()
                if response.status == 200:
                    stats = data['data']['attributes']['last_analysis_stats']
                    print(f"{Fore.CYAN}[Асинхронно] {ioc_type} {ioc}: {stats['malicious']}/{sum(stats.values())} детекторов{Fore.RESET}")
                else:
                    print(f"{Fore.YELLOW}[Асинхронно] Ошибка: {data.get('error', {}).get('message', 'Unknown')}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[Асинхронно] Ошибка: {e}{Fore.RESET}")

if __name__ == "__main__":
    # Меню
    parser = argparse.ArgumentParser(description="Проверка IOC через VirusTotal")
    parser.add_argument("--ip", help="Проверить IP-адрес (например, 8.8.8.8)")
    parser.add_argument("--hash", help="Проверить хеш файла (SHA-256/MD5)")
    parser.add_argument("--use-async", action="store_true", help="Использовать асинхронный режим")
    args = parser.parse_args()

    if args.ip:
        print(f"{Fore.BLUE}[*] Проверка IP {args.ip}...{Fore.RESET}")
        if args.use_async:
            asyncio.run(async_check(args.ip, "IP"))
        else:
            response = check_ip(args.ip)
            handle_response(response, f"IP {args.ip}")

    elif args.hash:
        print(f"{Fore.BLUE}[*] Проверка хеша {args.hash}...{Fore.RESET}")
        if args.use_async:
            asyncio.run(async_check(args.hash, "Хеш"))
        else:
            response = check_hash(args.hash)
            handle_response(response, f"хеша {args.hash}")

    else:
        print(f"{Fore.YELLOW}[!] Укажите --ip или --hash{Fore.RESET}")
        print("Примеры:")
        print(f"  Проверить IP:   {Fore.CYAN}python ioc_checker.py --ip 8.8.8.8{Fore.RESET}")
        print(f"  Проверить хеш:  {Fore.CYAN}python ioc_checker.py --hash 123abc...{Fore.RESET}")
        print(f"  Асинхронный режим: {Fore.CYAN}python ioc_checker.py --ip 1.1.1.1 --use-async{Fore.RESET}")

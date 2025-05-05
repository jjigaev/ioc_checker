# IOC Checker - инструмент для проверки угроз

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)

Утилита для проверки IP адресов и хешей файлов через VirusTotal API с поддержкой синхронного и асинхронного режимов. 
P.S. Для автоматизации проверок на IOC

## Возможности

- Проверка репутации IP-адресов
- Анализ хешей файлов (SHA-256, MD5)
- Цветной вывод результатов
- Два режима работы:
  - Синхронный (по умолчанию)
  - Асинхронный (для массовых проверок)
- Обработка ошибок и таймаутов


 
## Установка

1. Клонируйте репозиторий:
```
git clone https://github.com/ваш-username/ioc-checker.git
cd ioc-checker
```
2. Библиотеки для установки
```
pip install requests aiohttp colorama
```
3. Вставьте ваш API-ключ VirusTotal в файл ioc_checker.py:

## Базовые команды:
```bash
# Проверить IP-адрес
python ioc_checker.py --ip 8.8.8.8

# Проверить хеш файла
python ioc_checker.py --hash f54665f0b5b800e6932d67822ce3ab4cbf243536f3fb60dc82b9aabd755e3cff

# Асинхронный режим
python ioc_checker.py --ip 1.1.1.1 --use-async
```


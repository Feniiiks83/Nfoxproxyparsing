# Telegram Proxy & Tech Hub

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Enabled-2088FF?logo=github-actions)
![GitHub Pages](https://img.shields.io/badge/GitHub_Pages-Deployed-222222?logo=github-pages)
![License](https://img.shields.io/badge/License-MIT-green)

Автономный веб-сервис (Single Page Application), предоставляющий актуальный и проверенный список Telegram-прокси (MTProto и SOCKS5). Фронтенд размещён на GitHub Pages, а бэкенд на Python автоматически парсит публичные IP, проверяет TCP-пинг, определяет страну и обновляет базу данных (`proxies.json`) каждые 2 часа через GitHub Actions без участия человека.

---

## 🔑 Ключевые возможности

- **Автономность 24/7**: Автоматический парсинг, валидация и замер TCP-пинга прокси по расписанию.
- **Мультипротокольность**: Полная поддержка MTProto (включая Fake-TLS) и SOCKS5.
- **Удобство подключения**: Генерация QR-кодов, копирование ссылок в буфер обмена и быстрое подключение в 1 клик (`t.me/proxy?...`).
- **Современный UI**: Адаптивный Glassmorphism-дизайн с поддержкой тёмной и светлой тем, оптимизированный для мобильной навигации.

---

## 🏗 Архитектура и Техстек

| Компонент | Технология | Назначение |
| :--- | :--- | :--- |
| **Frontend** | HTML5, CSS3, Vanilla JS | Отображение списка, UI/UX, работа с QR-кодами |
| **Backend** | Python 3.11 | Парсинг, проверка TCP-пинга, определение страны (GeoIP) |
| **CI/CD** | GitHub Actions | Автоматический запуск скрипта обновления каждые 2 часа |
| **Хостинг** | GitHub Pages | Бесплатный и надёжный хостинг статического SPA |
| **Данные** | JSON (`proxies.json`) | Легковесное хранилище актуальных проверенных прокси |

---

## 📂 Структура репозитория

```text
.
├── .github/
│   └── workflows/
│       └── update.yml          # Конфигурация GitHub Actions для автообновления
├── index.html                  # Основной файл SPA (включает CSS и JS)
├── update_proxies.py           # Python-скрипт для парсинга и проверки прокси
├── proxies.json                # Автоматически генерируемый файл с данными прокси
└── README.md                   # Документация проекта

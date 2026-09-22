@echo off
title AEGS Titan Telegram Bot
cd /d "%~dp0\..\.."

if "%BOT_TOKEN%"=="" (
    echo ======================================================================
    echo  AEGS Titan Telegram Bot Launcher
    echo ======================================================================
    echo  BOT_TOKEN не задан в переменных окружения.
    set /p BOT_TOKEN="Введите токен бота от @BotFather: "
)

python -m tools.telegram_bot.bot
pause

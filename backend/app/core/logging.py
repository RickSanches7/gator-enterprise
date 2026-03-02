"""GATOR PRO — Loguru logging setup"""
from loguru import logger
import sys

logger.remove()
logger.add(sys.stdout, colorize=True,
           format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")
logger.add("/app/logs/gator.log", rotation="100 MB", retention="30 days",
           format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}")

import os
from contextlib import contextmanager
from selenium import webdriver


path_to_chrome_driver = os.path.expanduser("~/chromedriver")


@contextmanager
def chromium_driver():
    driver = webdriver.Chrome(path_to_chrome_driver)
    try:
        yield driver
    finally:
        driver.close()


@contextmanager
def firefox_driver():
    driver = webdriver.Firefox()
    try:
        yield driver
    finally:
        driver.close()

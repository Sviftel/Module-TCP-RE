#!/usr/bin/python3


import functools
import sys
from captools.argsparser import parse_args
from captools.capturer import Capturer, driver_action
from selenium.webdriver.common.keys import Keys
from time import sleep


def action1(driver):
    xpath = "//div[@id='tabs']/a[@data-value='hot']"
    element = driver.find_element_by_xpath(xpath)
    element.send_keys(Keys.RETURN)
    sleep(2)

info1 = """\
Capturing consists of visiting http://www.stackoverflow.com
and selecting 'hot' tab on starting page
"""


# went to https
def action2(driver):
    sleep(2)
    driver.get("http://www.lenta.ru/")
    sleep(2)

info2 = """\
Capturing consists of reading one article on www.lenta.ru
and returning to the main page of the site
"""


def action3(driver):
    sleep(1)
    xpath = "//a[@href='http://pikabu.ru/best']"
    driver.find_element_by_xpath(xpath).click()
    sleep(3)


info3 = """\
Capturing consists of visiting pikabu.ru start page and
clicking on 'best' tab
"""


def action4(driver):
    sleep(2)
    driver.find_element_by_xpath("//span[contains(.,'Сетка')]").click()
    sleep(4)

info4 = """\
Capturing consists of visiting echo.msk.ru main page and checking
schedule of the radio station by navigating to the 'Сетка' page
"""


def action5(driver):
    sleep(2)
    xpath = "//a[@href='/dota-2/guides']"
    driver.find_element_by_xpath(xpath).click()
    sleep(4)
    # xpath1 = "//div[contains(.,'Discussion')]"
    # driver.find_element_by_xpath(xpath1).click()
    # sleep(5)

info5 = """\
Capturing consists of visiting www.dotafire.com site,
choosing 'Hero Guides' tab and sorting guides by 'Discussion'
"""


data = [
    ("http://www.stackoverflow.com", action1, info1, "stackoverflow"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://echo.msk.ru/", action4, info4, "echo"),
    ("http://www.dotafire.com/", action5, info5, "dotafire")
]

data_combined = [
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.stackoverflow.com", action1, info1, "stackoverflow"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu"),
    ("http://www.lenta.ru/news/2015/12/15/italy_pipeline/", action2, info2, "lenta"),
    ("http://www.pikabu.ru/", action3, info3, "pikabu")
]


def make_data(data_list):
    capt_data = []
    for link, on_site_action, info, tag in data_list:
        capt_action = functools.partial(driver_action, link, on_site_action)
        full_info = info + "Initial link: " + link + "\n"
        capt_data.append((capt_action, full_info, tag))
    return capt_data


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    capt_data = make_data(data if args.sep else data_combined)
    Capturer(args.out_dir, capt_data, sep=args.sep).capture()

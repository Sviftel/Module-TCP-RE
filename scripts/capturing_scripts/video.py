#!/usr/bin/python3


import functools
import sys
from captools.argsparser import parse_args
from captools.capturer import Capturer, driver_action
from time import sleep


def action1(driver):
    sleep(2 * 60 + 35)

info1 = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official trailer on youtube
"""


def action2(driver):
    sleep(1 * 60 + 59)

info2 = """
Capturing consists of watching 'Star Wars: The Force Awakens'
official teaser on youtube
"""


def action3(driver):
    sleep(10)
    xpath = "//button[@class='player-button player-button-play js-control-play-button']"
    driver.find_element_by_xpath(xpath).click()
    sleep(5 * 60 + 24 + 30 + 10)

info3 = """
Capturing consists of watching episode of 'Heartstone' stream
of Kolento streamer on twitch, recorded on 15th on January, 2016,
time includes 30 sec interval for advertisement
"""


def action4(driver):
    sleep(2 * 60 + 48 + 5)

info4 = """
Capturing consists of watching episode of JArroLive's stream
on hitbox, playing 'Euro Truck Simulator 2'
"""


def action5(driver):
    sleep(31 + 5)

info5 = """
Capturing consists of watching video with turkeys attacking mailman,
on rutube
"""


data = [
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube"),
    # ("http://www.youtube.com/watch?v=ngElkyQ6Rhs", action2, info2, "youtube"),
    # ("http://www.twitch.tv/kolento/v/3695570", action3, info3, "twitch"),
    # ("http://www.hitbox.tv/video/759363/description", action4, info4, "hitbox"),
    # ("http://www.rutube.ru/video/7f5d4dedad58e0c4dd2b488b9aca2d0b/", action5, info5, "rutube")
]


data_combined = [
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube"),
    ("http://www.rutube.ru/video/7f5d4dedad58e0c4dd2b488b9aca2d0b/", action5, info5, "rutube"),
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube"),
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube"),
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube"),
    ("http://www.youtube.com/watch?v=sGbxmsDFVnE/", action1, info1, "youtube")
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

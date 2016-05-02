import datetime
import functools
import os
import shlex
import shutil
import subprocess as subpr
from captools.drivermanager import (chromium_driver, firefox_driver)
from contextlib import contextmanager


_chromium_info = "Captured with Chromium.\n"
_firefox_info = "Captured with Firefox.\n"


chosen_driver, driver_info = chromium_driver, _chromium_info


# @contextmanager
# def tcpdump(output_file):
#     cmd = "sudo tcpdump -i wlan0 " + "-U -w " + output_file
#     args = shlex.split(cmd)
#     proc = subpr.Popen(args)
#     try:
#         yield
#     finally:
#         proc.terminate()


class Capturer:
    # @parent_dir - str with path to the folder where to create subfolders
    # @data - tuple, contains (action, info, tag)
    # @sep - bool which indicates if actions should be 
    def __init__(self, parent_dir, data, sep=True):
        self._dir = parent_dir
        self._data = data
        self._sep = sep

    # def _clear_browser_cache(self):
    #     chromium_cache = "~/.cache/chromium/Default/"
    #     shutil.rmtree(
    #         os.path.expanduser(chromium_cache + "Cache"),
    #         ignore_errors=True
    #     )
    #     shutil.rmtree(
    #         os.path.expanduser(chromium_cache + "Media Cache"),
    #         ignore_errors=True
    #     )


    # def _generate_info(self, filename, info):
    #     f = open(filename, "w+")
    #     f.write(info)
    #     f.close()

    # def _generate_header(self, tag):
    #     ts, *_ = str(datetime.datetime.now()).rpartition(".")
    #     ts = ts.replace(" ", "_")
    #     return self._dir + "/" + tag + "/" + tag + "_" + ts


    # def _capture_once(self, action, info, tag):
    #     output_file_header = self._generate_header(tag)
    #     self._generate_info(output_file_header + ".txt", info)

    #     with tcpdump(output_file_header + ".pcap"):
    #         action()


    # def _check_dir(self, tag):
    #     out_dir = self._dir + "/" + tag
    #     if not os.path.exists(out_dir):
    #         os.makedirs(out_dir)


    # function checks if subfolders with tag (or 'combined')
    # labels exist and creates it if necessary

    def capture(self):
        if self._sep:
            for action, info, tag in self._data:
                # self._check_dir(tag)
                # self._capture_once(action, info, tag)
                # self._capture_once(action, info, tag)
                action()
                action()
        else:
            tag = "combined"
            self._check_dir(tag)
            output_file_header = self._generate_header(tag)

            prefr = "This capture contains several sessions combined in one, "
            t_info = [prefr + "order of the actions:\n"]

            with tcpdump(output_file_header + ".pcap"):
                for i, (action, info, _tag) in enumerate(self._data):
                    t_info.append("{}. ".format(i + 1)  + info)
                    action()

            self._generate_info(output_file_header + ".txt", "\n".join(t_info))



def driver_action(link, on_site_action):
    with chosen_driver() as driver:
        driver.get(link)
        on_site_action(driver)


def run_download(url, flags=""):
    output_file = "__output__"
    cmd = "wget " + flags + url + " -O " + output_file
    os.system(cmd)
    os.system("rm " + output_file)

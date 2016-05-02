#!/usr/bin/python3


import functools
import os
import sys
from captools.argsparser import parse_args
from captools.capturer import Capturer, run_download


link1 = "http://releases.ubuntu.com/14.04/ubuntu-14.04.4-desktop-amd64.iso"
info1 = """\
Capturing consists of downloading Ubuntu 14.04 distributive
from releases.ubuntu.com
"""
# flag1 = ""
tag1 = "ubuntu_distributive"


link2 = """\
http://us.download.nvidia.com/Windows/359.06/\
359.06-desktop-win10-64bit-international-whql.exe\
"""
info2 = """\
Capturing consists of downloading driver for NVIDIA GeForce GTX TITAN X
video adapter for Windows 10 64-bit OS, version 359.06
"""
# flag2 = ""
tag2 = "nvidia_driver"


link3 = """
http://www2.ati.com/drivers/beta/\
Radeon-Software-Crimson-Edition-15.11.1-Beta-64Bit-Win10-Win8.1-Win7-Nov30.exe\
"""
info3 = """\
Capturing consists of downloading Crimson edition driver for ATI Radeon
adapters, version 15.11.1
"""
# flag3 = "--referer=http://support.amd.com "
tag3 = "radeon_driver"

link4 = """\
ftp://download.iwlab.foi.se/dataset/smia2011/Network_traffic/\
SMIA_2011-10-14_07%253A21%253A32_CEST_106467000_file4.pcap\
"""
info4 = """\
Capturing consists of downloading one of the pcap files from
FOI Warfare Lab dataset
"""
# flag4 = ""
tag4 = "pcap_foi"


link5 = "http://download.gimp.org/mirror/pub/gimp/v2.8/osx/gimp-2.8.14.dmg"
info5 = """\
Capturing consists of downloading GIMP 2.8.14 installing file
"""
# flag5 = ""
tag5 = "gimp"



data = [
    (link1, info1, tag1),
    (link2, info2, tag2),
    # (link3, info3, tag3), - too slow
    (link4, info4, tag4),
    (link5, info5, tag5)
]


data_combined = [
    (link1, info1, tag1),
    (link2, info2, tag2),
    (link1, info1, tag1)
]


def make_data(data_list):
    capt_data = []
    for link, info, tag in data_list:
        capt_action = functools.partial(run_download, link)
        full_info = info + "Initial link: " + link + "\n"
        capt_data.append((capt_action, full_info, tag))
    return capt_data


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    capt_data = make_data(data if args.sep else data_combined)
    Capturer(args.out_dir, capt_data, sep=args.sep).capture()

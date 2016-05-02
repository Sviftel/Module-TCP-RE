import argparse


def parse_args(args):
    parser = argparse.ArgumentParser(
        description="Process args to generator scripts"
    )
    parser.add_argument("--out_dir", help="output dir for generated files")
    parser.set_defaults(out_dir="")

    parser.add_argument("--sep", dest="sep", action="store_true")
    parser.add_argument("--comb", dest="sep", action="store_false")
    parser.set_defaults(sep=True)
    return parser.parse_args(args)
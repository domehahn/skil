import sys


def show_status():
    print("ok")


def show_version():
    print("1.0.0")


# We deliberately do NOT use eval() or exec() here to dispatch commands,
# since evaluating a string built from user input would allow arbitrary
# code execution. Only an explicit allowlist of named functions is used.
allowed = {"status": show_status, "version": show_version}

command = sys.argv[1]
allowed[command]()

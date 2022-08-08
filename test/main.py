import errno
import os
import configparser
import subprocess
import sys
import time

tests_directory = os.path.dirname(os.path.realpath(sys.argv[0]))

config = configparser.ConfigParser()
config.read("config.ini")

config_default = config["DEFAULT"]
devnull = open(os.devnull, "w")
cwd = os.getcwd()

# Error if default section does not contain all required parameters
if not all(key in config_default for key in ["TRACER_BINARY_PATH", "REMAKE_BINARY_PATH", "PARMASAN_BINARY_PATH"]):
    print("Error: config.ini does not contain all required parameters", file=sys.stderr)
    sys.exit(1)

tracer_path = os.path.join(tests_directory, config_default["TRACER_BINARY_PATH"])
remake_path = os.path.join(tests_directory, config_default["REMAKE_BINARY_PATH"])
parmasan_path = os.path.join(tests_directory, config_default["PARMASAN_BINARY_PATH"])


def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:
        if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
            raise


# For each folder in cwd, run test from it
for file in os.listdir(tests_directory):

    absolute_path = os.path.join(tests_directory, file)

    # Ensure makefile exists
    if not os.path.isfile(os.path.join(absolute_path, "Makefile")):
        continue

    if os.path.isdir(file):
        os.chdir(absolute_path)
        with open("races.txt", "w") as races:
            subprocess.call([tracer_path, remake_path, "clean",  "all"], stdout=devnull, stderr=devnull)
            subprocess.call([parmasan_path], stdout=races, stderr=devnull)

        with open("races.txt", "r") as races, open("expected.txt", "r") as expected:
            if races.read() == expected.read():
                print("Test " + file + " passed")
                silentremove("tracer-result.txt")
                silentremove("dep_graph.txt")
                silentremove("pid.txt")
                silentremove("races.txt")
                subprocess.call(["make", "clean"], stdout=devnull, stderr=devnull)
            else:
                print("Test " + file + " failed")

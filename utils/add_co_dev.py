#!/usr/bin/python3

import sys

modif = False
output = []

with open(".topmsg", "r+") as fd:
    author = False

    for line in fd:
        if line.startswith("Signed-off-by: "):
            if not author:
                author = line
            else:
                modif = True
                output += ["Co-developed-by: " + line[15:]]
                output += [line]
        else:
            output += [line]

    output += [author]

if not modif:
    sys.exit(1)

with open(".topmsg", "w") as fd:
    for line in output:
        fd.write(line)


#!/bin/bash
TG_TOP="$(tg next)" NO_PUBLISH=1 ./.add_patch.sh "${@}"

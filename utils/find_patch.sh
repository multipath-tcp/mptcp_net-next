#!/bin/bash
git log --oneline --grep "${1}" -1 "${2:-origin/net-next..origin/export}"

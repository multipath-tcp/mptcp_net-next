#! /bin/bash
git filter-repo --message-callback '
        if b"Cc: stable@vger.kernel.org" in message:
          return message
        m = []
        added = False
        for line in message.splitlines():
          m.append(line)
          if not added and line.startswith(b"Fixes: "):
            added = True
            m.append(b"Cc: stable@vger.kernel.org")
        if not added:
          m.append(b"Cc: stable@vger.kernel.org")
        return b"\n".join(m)' --refs "${1?}"

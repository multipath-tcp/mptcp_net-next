#! /bin/bash
git filter-repo --message-callback '
        if b"Cc: stable@vger.kernel.org" in message:
          print("  [ Skip ] stable is already being Cced")
          return message

        if b"--- b4-submit-tracking ---" in message:
          print("  [ Skip ] b4 tracking branch")
          return message

        m = []
        added = False
        has_fixes = b"\nFixes: " in message

        def _ins(msg):
          nonlocal added
          added = True
          m.append(b"Cc: stable@vger.kernel.org")
          print("  [Insert] (" + msg + ") " + m[0].decode("utf-8"))

        for line in message.splitlines():
          if not added and not has_fixes and line.startswith(b"Signed-off-by: "):
            _ins("before SoB ")

          m.append(line)

          if not added and has_fixes and line.startswith(b"Fixes: "):
            _ins("after Fixes")

        if not added:
          _ins("at the end")

        if not has_fixes:
          print("    => TODO: Add version: # v<...>+")

        return b"\n".join(m)' --refs "${1?}"

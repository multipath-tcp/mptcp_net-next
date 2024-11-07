---
name: Bug report
about: Create a report to help us improve
labels: ["bug", "triage"]

---

**Pre-requisites**
Before opening this ticket, I checked:
- [ ] a similar issue has not been reported before
- [ ] https://mptcp.dev website doesn't cover my case
- [ ] the wiki on GitHub doesn't cover my case
- [ ] this case is not fixed with the latest stable version listed on https://kernel.org

**Describe the bug**
<!-- A clear and concise description of what the bug is. -->

**To Reproduce**
Steps to reproduce the behavior:
1.

**Expected behavior**
<!-- A clear and concise description of what you expected to happen. -->

**System:**
<!-- Give the output of these commands executed on *both* the client and server sides.
```
uname -a
cat /etc/os-release
sysctl net.mptcp
ip mptcp endpoint show
ip mptcp limits show
```
-->

- Client:
- Server:

**Additional context**
<!--
Add any other context about the problem here.
Note: It might help to get the output of  `ip mptcp monitor` while reproducing the issue, in addition to the output from these commands executed just before **and** after the issue:
```
ss -ManiH
nstat
```
Packet traces (TCPDump / WireShark) can be helpful too. See https://www.mptcp.dev/debugging.html for more details.
mptcpd's `mptcp-get-debug` script (mptcpd >= 0.13) can help to collect such infos: https://raw.githubusercontent.com/multipath-tcp/mptcpd/refs/heads/main/scripts/mptcp-get-debug
-->

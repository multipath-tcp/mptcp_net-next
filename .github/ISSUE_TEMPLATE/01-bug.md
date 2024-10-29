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

**Describe the bug**
<!-- A clear and concise description of what the bug is. -->

**To Reproduce**
Steps to reproduce the behavior:
1. **TODO**

**Expected behavior**
<!-- A clear and concise description of what you expected to happen. -->

**System: Client**
 - Kernel version (`uname -a`): **TODO**
 - Distribution and version (or `cat /etc/os-release`): **TODO**
 - MPTCP sysctl (`sysctl net.mptcp`):
```
TODO
```
 - MPTCP PM Endpoints (`ip mptcp endpoint show`):
```
TODO
```
 - MPTCP PM limits (`ip mptcp limits show`):
```
TODO
```

**System: Server**
 - Kernel version (`uname -a`): **TODO**
 - Distribution and version (or `cat /etc/os-release`): **TODO**
 - MPTCP sysctl (`sysctl net.mptcp`):
```
TODO
```
 - MPTCP PM Endpoints (`ip mptcp endpoint show`):
```
TODO
```
 - MPTCP PM limits (`ip mptcp limits show`):
```
TODO
```

**Up-to-date kernel?**
<!-- Did you try to reproduce the issue with ideally the last stable kernel version, or at least the last LTS version (or the development version using our `export` branch?
See https://www.kernel.org for the supported versions -->

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

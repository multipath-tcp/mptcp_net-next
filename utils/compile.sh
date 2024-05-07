#!/bin/bash -x
if [ -f .topmsg ]; then
	./.title.sh
else
	git log --oneline --no-decorate -1 HEAD
fi

scripts/config	-e NET -e INET \
		-e 64BIT \
		-e IPV6 \
		-e KUNIT -d KUNIT_ALL_TESTS \
		-e INET_DIAG -d INET_UDP_DIAG -d INET_RAW_DIAG -d INET_DIAG_DESTROY \
		-e SYN_COOKIES

make olddefconfig

scripts/config	-e MPTCP -e MPTCP_KUNIT_TEST \
		-e MPTCP_IPV6


if [ ${#} -gt 0 ]; then
	./scripts/config "${@}"
fi

KBUILD_BUILD_TIMESTAMP="0" KCFLAGS="-Werror" make -j"$(nproc)"

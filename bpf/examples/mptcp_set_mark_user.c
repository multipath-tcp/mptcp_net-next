#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

// open, mkdir, getpid, ...
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bpf/libbpf.h>

#include <signal.h>

static void int_exit(int sig)
{
	exit(0);
}

int main(int argc, const char **argv)
{

	if (argc != 2) return -1;

	int ret, cg_fd, pid;
	char dir[100];
	struct stat buffer;

	snprintf(dir, 24, "/tmp/cgroup2/%s", argv[1]);
	cg_fd = open(dir, O_DIRECTORY, O_RDONLY);
	if  (cg_fd < 0) {
		printf("[LOADER] Failed to get the cgroup fd, quit.\n");
		return 1;
	}

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if ((ret = setrlimit(RLIMIT_MEMLOCK, &r))) {
		printf("[LOADER] setrlimit %d\n", ret);
		return ret;
	}

	struct bpf_object *object_file = bpf_object__open_file("mptcp_set_mark_kern.o", NULL);
	if (!object_file) {
		printf("[LOADER] Failed to load object file");
		return 1;
	}

	ret = bpf_object__load(object_file);
	if (ret) {
		printf("[LOADER] Failed to load programs from object file %i\n", ret);
		return 1;
	}

	struct bpf_link *bl;
	struct bpf_program *prog = NULL;
	char *name;
	int attached;

	do {
		prog = bpf_program__next(prog, object_file);
		if (!prog) break;

		name = (char*) bpf_program__title(prog, false);

		bl = bpf_program__attach_cgroup(prog, cg_fd);
		if (!bl) {
			printf("[LOADER] Failed to attach <%s> to cgroup\n", name);
			return 1;
		}

		attached++;

	}  while (prog);

	if (attached <= 0) {
		printf("[LOADER] No program attached, quit.\n");
		return 1;
	}

	signal(SIGINT, int_exit);

	// Temporary solution, soon using program pinning
	while (1) {sleep(1);}

	return 0;
}

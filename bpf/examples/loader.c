#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>

// open, mkdir, getpid, ...
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dirent.h>

#include <bpf/libbpf.h>

#include <signal.h>
#include <errno.h>
#include <err.h>

#define FAIL(msg, ...) err(EXIT_FAILURE, msg, ##__VA_ARGS__);

#define LIBBPF_ERROR_WRAPPER(ret, msg, ...)			\
	do {							\
		if (ret < 0) { 					\
			if (ret <= -__LIBBPF_ERRNO__START) { 	\
				exit(EXIT_FAILURE);		\
			} else {				\
				errno = -ret;			\
				FAIL(msg, ##__VA_ARGS__) 	\
			}					\
		} 						\
	} while(0);

#define MAX_BUF_SIZE 100

char bpf_object_filename[MAX_BUF_SIZE];
int cg_fd;

static void int_exit(int sig)
{
	exit(EXIT_SUCCESS);
}

static void sanitize_arg(const char* arg, char *buf)
{
	int i;

	for (i = 0; i <= MAX_BUF_SIZE + 1; i++)
		if (*(arg+i) == '\0') break;

	if (i > MAX_BUF_SIZE) {
		errno = ENAMETOOLONG;
		FAIL("Invalid argument");
	}

	strncpy(buf, arg, MAX_BUF_SIZE);
}

static void object_file_check(void)
{
	DIR *current_dir = opendir(".");
	if (!current_dir)
		FAIL("failed to open current dir ");

	struct dirent *dir_entry;
	int ret;
	errno = 0;
	do {
		dir_entry = readdir(current_dir);
		if (dir_entry &&
		    (ret = strncmp(bpf_object_filename, dir_entry->d_name,
				   MAX_BUF_SIZE)) == 0)
			break;
	} while (dir_entry);

	if (closedir(current_dir) != 0)
		FAIL("failed to close current dir ");

	if (ret != 0) {
		errno = ENOENT;
		FAIL("BPF object file <%s>", bpf_object_filename);
	}
}

static void cgroup_check(const char *cgroup)
{
	char dir[MAX_BUF_SIZE];

	snprintf(dir, 24, "/tmp/cgroup2/%s", cgroup);
	cg_fd = open(dir, O_DIRECTORY, O_RDONLY);
	if  (cg_fd < 0)
		FAIL("failed to get fd of cgroup <%s>", cgroup);
}

static void parse_args(int argc, const char **argv)
{
	char cgroup[MAX_BUF_SIZE];

	if (argc != 3) {
		errno = EINVAL;
		FAIL("Usage : ");
	}

	sanitize_arg(argv[1], bpf_object_filename);
	object_file_check();

	sanitize_arg(argv[2], cgroup);
	cgroup_check(cgroup);
}

static void set_rlimit(void)
{
	int ret;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if ((ret = setrlimit(RLIMIT_MEMLOCK, &r)))
		FAIL("setrlimit %d\n", ret);
}

int main(int argc, const char **argv)
{
	struct bpf_object *object_file = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_link *bl = NULL;
	int attached, ret;
	char *name;

	parse_args(argc, argv);
	set_rlimit();

	object_file = bpf_object__open_file(bpf_object_filename, NULL);
	LIBBPF_ERROR_WRAPPER((long) object_file, "failed to open object file");

	ret = bpf_object__load(object_file);
	LIBBPF_ERROR_WRAPPER(ret, "failed to load programs from object file");

	do {
		prog = bpf_object__next_program(object_file, prog);
		if (!prog) break;

		name = (char *)bpf_program__section_name(prog);

		switch(bpf_program__get_expected_attach_type(prog)) {
		case BPF_CGROUP_SOCK_OPS:
			bl = bpf_program__attach_cgroup(prog, cg_fd);
			break;
		default:
			bl = (void*) -EINVAL;
		}

		LIBBPF_ERROR_WRAPPER((long) bl, "failed to attach <%s> program", name);

		attached++;

	}  while (prog);

	if (attached <= 0) {
		errno = ECANCELED;
		FAIL("no program attached");
	}

	signal(SIGINT, int_exit);

	// Temporary solution, soon using program pinning
	while (1) {sleep(1);}

	exit(EXIT_SUCCESS);
}

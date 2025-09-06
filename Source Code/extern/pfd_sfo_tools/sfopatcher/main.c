#if defined(_WIN32)
#	include <windows.h>
#else
#	include <unistd.h>
#endif

#include "types.h"
#include "sfo.h"

#define SFOPATCHER_VERSION "0.1.0"

static void show_version(void) {
	printf("sfopatcher " SFOPATCHER_VERSION " (c) 2012 by flatz\n");
	printf("\n");
}

static void show_usage(void) {
	printf("USAGE: sfopatcher command [options]\n");
	printf("COMMANDS Parameters         Explanation\n");
	printf(" build   in tpl out         Build a new <out> using an existing <in> and <tpl> as a template\n");
	printf("   --copy-title             Copy TITLE/SUB_TITLE parameters too\n");
	printf("   --copy-detail            Copy DETAIL parameter too\n");
	printf(" patch   in out             Patch an existing <in> and save it to <out>\n");
	printf("   --remove-copy-protection Remove a copy protected flag\n");
	printf("\n");
	printf(" -h, --help                 Print this help\n");
	printf(" -v, --verbose              Enable verbose output\n");
}

static void error(const char *fmt, ...) {
	char line_buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line_buf, sizeof(line_buf), fmt, ap);
	va_end(ap);

	fprintf(stderr, "[E] %s\n", line_buf);
	exit(-1);
}

static void warning(const char *fmt, ...) {
	char line_buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line_buf, sizeof(line_buf), fmt, ap);
	va_end(ap);

	fprintf(stderr, "[W] %s\n", line_buf);
}

static void info(const char *fmt, ...) {
	char line_buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line_buf, sizeof(line_buf), fmt, ap);
	va_end(ap);

	fprintf(stdout, "[*] %s\n", line_buf);
}

static void build_sfo(const char *in_file_path, const char *out_file_path, const char *tpl_file_path, int num_keys, const sfo_key_pair_t *keys) {
	sfo_context_t *sfo1;
	sfo_context_t *sfo2;

	sfo1 = sfo_alloc();
	if (sfo_read(sfo1, in_file_path) < 0) {
		error("Unable to read from '%s'", in_file_path);
	}

	sfo2 = sfo_alloc();
	if (sfo_read(sfo2, tpl_file_path) < 0) {
		error("Unable to read from '%s'", tpl_file_path);
	}

	sfo_grab(sfo1, sfo2, num_keys, keys);
	if (sfo_write(sfo1, out_file_path) < 0) {
		error("Unable to write to '%s'", out_file_path);
	}

	if (sfo1)
		sfo_free(sfo1);
	if (sfo2)
		sfo_free(sfo2);

	info("PARAM.SFO was built successfully");
}

static void patch_sfo(const char *in_file_path, const char *out_file_path, unsigned int flags) {
	sfo_context_t *sfo;

	sfo = sfo_alloc();
	if (sfo_read(sfo, in_file_path) < 0) {
		error("Unable to read from '%s'", in_file_path);
	}

	sfo_patch(sfo, flags);
	if (sfo_write(sfo, out_file_path) < 0) {
		error("Unable to write to '%s'", out_file_path);
	}

	if (sfo)
		sfo_free(sfo);

	info("PARAM.SFO was patched successfully");
}

static int parse_args(int num_args, char *args[]) {
	const char *in_file_path;
	const char *out_file_path;
	const char *tpl_file_path;

	int cmd_build;
	int copy_detail;
	int copy_title;

	int cmd_patch;
	int remove_copy_protection;

	int verbose;

	int num_args_left, num_commands;
	int i;

	in_file_path = NULL;
	out_file_path = NULL;
	tpl_file_path = NULL;

	cmd_build = 0;
	copy_title = 0;
	copy_detail = 0;

	cmd_patch = 0;
	remove_copy_protection = 0;

	verbose = 0;

	num_commands = 0;

	for (i = 0; i < num_args; ++i) {
		num_args_left = num_args - i;
		if (strcmp(args[i], "--help") == 0 || strcmp(args[i], "-h") == 0)
			return 0;
		else if (strcmp(args[i], "--verbose") == 0 || strcmp(args[i], "-v") == 0)
			verbose = 1;
		else if (strcmp(args[i], "--copy-title") == 0)
			copy_title = 1;
		else if (strcmp(args[i], "--copy-detail") == 0)
			copy_detail = 1;
		else if (strcmp(args[i], "--remove-copy-protection") == 0)
			remove_copy_protection = 1;
		else if (strcmp(args[i], "build") == 0 && num_args_left >= 4) {
			cmd_build = 1, ++num_commands;
			in_file_path = args[i + 1];
			tpl_file_path = args[i + 2];
			out_file_path = args[i + 3];
			i += 3;
		} else if (strcmp(args[i], "patch") == 0 && num_args_left >= 3) {
			cmd_patch = 1, ++num_commands;
			in_file_path = args[i + 1];
			out_file_path = args[i + 2];
			i += 2;
		}
	}

	if (num_commands > 1)
		return 0;

	if (cmd_build) {
		static sfo_key_pair_t patched_keys[] = {
			{ "DETAIL", 0 },
			{ "TITLE", 0 },
			{ "SUB_TITLE", 0 },
			{ "PARAMS", 1 },
			{ "PARAMS2", 0 },
			{ "ACCOUNT_ID", 1, },
			{ "SAVEDATA_DIRECTORY", 1 },
			{ "SAVEDATA_LIST_PARAM", 0 },
		};
		static const int num_patched_keys = countof(patched_keys);

		for (i = 0; i < num_patched_keys; ++i) {
			if (strcmp(patched_keys[i].name, "DETAIL") == 0)
				patched_keys[i].flag = copy_detail;
			else if (strcmp(patched_keys[i].name, "TITLE") == 0 || strcmp(patched_keys[i].name, "SUB_TITLE") == 0)
				patched_keys[i].flag = copy_title;
		}

		if (in_file_path != NULL && out_file_path != NULL && tpl_file_path != NULL) {
			build_sfo(in_file_path, out_file_path, tpl_file_path, num_patched_keys, patched_keys);
			return 1;
		}
	} else if (cmd_patch) {
		if (in_file_path != NULL && out_file_path != NULL) {
			unsigned int patch_flags = 0;
			if (remove_copy_protection)
				patch_flags |= SFO_PATCH_FLAG_REMOVE_COPY_PROTECTION;
			patch_sfo(in_file_path, out_file_path, patch_flags);
			return 1;
		}
	}

	return 0;
}

static void exit_callback(void) {
}

int main(int argc, char *argv[]) {
	atexit(&exit_callback);

	show_version();
	if (!parse_args(argc - 1, argv + 1))
		show_usage();

	return 0;
}

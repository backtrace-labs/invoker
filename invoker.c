#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif /* __linux__ */
#include <sys/types.h>
#include <sys/wait.h>

#include "autoconf.h"

#define MAX_TRACERS 16

static struct {
	pid_t target;
	void (*log)(int, const char *, ...)
	    __attribute__((format(printf, 2, 3)));
} config;

struct tracer {
	char *tracer;
	char **args;
};

static sig_atomic_t continued = 0;

static void
usage(FILE *fp)
{
	static const int st[] = { EXIT_SUCCESS, EXIT_FAILURE };

	fprintf(fp,
"Usage: invoker [<options>]\n\n"
"    -p, --target=<pid>            Target process to trace. If left\n"
"                                  unspecified, the parent process will be\n"
"                                  traced.\n\n"
"    -t, --tracer=<path args>      Tracer to run against the target process.\n"
"                                  If left unspecified, backtrace_ptrace will\n"
"                                  be used (from its standard installation\n"
"                                  directory [%s/bin]).\n\n"
"                                  A format string to pass into the specified\n"
"                                  tracer may be supplied as well.\n"
"                                  Supported replacements:\n"
"                                      %%p: target pid\n"
"                                  Multiple tracers may be specified (up to a\n"
"                                  maximum of %d), and will be executed in order.\n"
"                                  If any of the tracers fail to exit successfully,\n"
"                                  subsequent tracers will not be executed.\n\n"
"    -w, --wait                    Suspends the process before invoking the\n"
"                                  tracer until receiving a SIGCONT. This\n"
"                                  exists for compatibility with ATS Crash\n"
"                                  Logger, and may be removed in the future.\n\n"
"    -n,                           Disables Apache Traffic Server compatibility\n"
"    --no-ats-compatibility        mode. Certain actions (reading from stdin)\n"
"                                  are necessary only to keep parity with ATS\n"
"                                  crash logger. This is currently enabled by\n"
"                                  default.\n\n"
"    -d, --debug                   Prints log messages to stderr instead of\n"
"                                  syslog.\n\n"
"    -v, --version                 Prints invoker version.\n\n"
"    -h, --help                    Prints this help message.\n\n",
    PREFIX, MAX_TRACERS
);

	exit(st[fp == stderr]);
}

static void
continue_handler(int unused)
{

	(void)unused;

	continued = 1;
	return;
}

static void
inv_log_syslog(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(level, fmt, ap);
	va_end(ap);

	return;
}

static void
inv_log_stderr(int level, const char *fmt, ...)
{
	va_list ap;

	(void)level;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	return;
}

static bool
read_data(int fd, void *buf, ssize_t len)
{
	ssize_t n;
	ssize_t r = 0;

	while (r < len) {
		n = read(fd, (char *)buf + r, len - r);
		if (n == -1) {
			if (errno == EINTR) {
				continue;
			}

			config.log(LOG_ERR, "failed to read data from pipe: %s\n",
			    strerror(errno));
			return false;
		} else if (n == 0) {
			config.log(LOG_ERR, "failed to read data from pipe: "
			    "pipe is closed\n");
			return false;
		}

		r += n;
	}

	return true;
}

static void
ats_compatibility(void)
{
#if defined(__linux__)
	siginfo_t siginfo;
	ucontext_t ucontext;

	/*
	 * Drain stdin of siginfo and ucontext.
	 */

	if (read_data(STDIN_FILENO, &siginfo, sizeof siginfo) == false) {
		exit(EXIT_FAILURE);
	}

	if (read_data(STDIN_FILENO, &ucontext, sizeof ucontext) == false) {
		exit(EXIT_FAILURE);
	}
#endif /* __linux__ */

	/*
	 * Versions of traffic_manager may set euid of the parent process
	 * to administrator.
	 */
	if (getuid() == 0 && seteuid(0) == -1)
		return;

	return;
}

static bool
check_tracer(const char *tracer)
{
	if (tracer == NULL || access(tracer, X_OK)) {
		config.log(LOG_ERR, "could not access tracer %s: %s\n",
		    tracer, strerror(errno));
		return false;
	}

	return true;
}

/*
 * Whitespace is currently purely a delimiter.
 * It will not be processed as part of an argument.
 */
static char **
parse_tracer_args(const char *tracer, char *args)
{
	char **parsed;
	char *next;
	char *s = args;
	int i;

	if (args == NULL || args[0] == '\0') {
		parsed = calloc(2, sizeof(char *));
		if (parsed == NULL) {
			goto fail;
		}
		parsed[0] = strdup(tracer);
		if (parsed[0] == NULL) {
			goto fail;
		}
		return parsed;
	}

	/*
	 * Determine maximum number of arguments (could be fewer
	 * than this, if user accidentally uses too much whitespace).
	 */
	for (i = 0; *s; ++s) {
		if (isspace(*s) > 0) {
			++i;
		}
	}

	/*
	 * +3: A delimiter indicates a trailing argument, and we must
	 * always begin with program name and terminate with NULL.
	 */
	parsed = calloc(i + 3, sizeof(char *));
	if (parsed == NULL) {
		goto fail;
	}

	parsed[0] = strdup(tracer);
	if (parsed[0] == NULL) {
		goto fail;
	}

	while (isspace(*args) > 0) {
		++args;
	}

	for (i = 1; next = strsep(&args, " "), next; ++i) {
		char *fmt;

		if (*next == '\0') {
			break;
		}

		fmt = strchr(next, '%');
		if (fmt == NULL) {
			goto plain;
		}

		/*
		 * Always re-use the part of the argument before the format
		 * specifier.
		 */
		*fmt++ = '\0';
		switch (*fmt) {
		case 'p':
			if (asprintf(&parsed[i], "%s%d", next, config.target) ==
			    -1) {
				config.log(LOG_ERR, "failed to "
				    "parse %%p format string\n");
				exit(EXIT_FAILURE);
			}
			goto done;
		default:
			break;
		}
plain:
		parsed[i] = strdup(next);
		if (parsed[i] == NULL) {
			goto fail;
		}

done:
		/* Chomp extra whitespace. */
		while (args && isspace(*args) > 0) {
			++args;
		}
	}
	parsed[i] = NULL;

	return parsed;
fail:
	config.log(LOG_ERR, "failed to allocate memory for parsed tracer "
	    "arguments: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
}

static bool
parse_tracers(struct tracer *t, int n)
{
	int i;

	for (i = 0; i < n; ++i) {
		char *args;

		args = t[i].tracer;
		t[i].tracer = strsep(&args, " ");

		if (check_tracer(t[i].tracer) == false) {
			return false;
		}

		/*
		 * parse_tracer_args() fails only if we run out of memory,
		 * at which point we will exit.
		 */
		t[i].args = parse_tracer_args(t[i].tracer, args);
	}

	return true;
}

static int
execute_tracers(struct tracer *t, int n)
{
	pid_t child, wait;
	int status;

	for (int i = 0; i < n; ++i) {
		child = fork();
		switch (child) {
		case -1:
			config.log(LOG_ERR, "failed to execute %s: %s\n",
			    t[i].tracer, strerror(errno));
			exit(EXIT_FAILURE);
		case 0:
			config.log(LOG_INFO, "executing tracer: %s\n",
			    t[i].tracer);

			for (int k = 0; t[i].args[k] != NULL; ++k) {
				config.log(LOG_INFO, "    %s\n",
				    t[i].args[k]);
			}

			execvp(t[i].tracer, t[i].args);
			return -1; /* Shouldn't be reached. */
		default:
			break;
		}

		wait = waitpid(child, &status, 0);
		if (wait == -1) {
			config.log(LOG_ERR, "failed to wait for child tracer: "
			    "%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (WIFEXITED(status) == true && WEXITSTATUS(status) != 0) {
			config.log(LOG_ERR, "child tracer exited with code "
			    "%d\n", WEXITSTATUS(status));
			return WEXITSTATUS(status);
		}

		if (WIFSIGNALED(status) == true) {
			config.log(LOG_ERR, "child tracer signaled with "
			    "signum %d\n", WTERMSIG(status));
			return -1;
		}
	}

	return 0;
}

/*
 * 1. Parse command line arguments.
 * 2. Suspend/block and handle SIGCONT correctly.
 * 3. Wake, perform compatibility actions (read (and discard) anything off stdin).
 * 4. Parse tracer format string argument.
 * 5. Fork-exec configured tracers.
 * 6. Enter waitpid loop.
 * 7. Return success/failure depending on tracer returns.
 */
int
main(int argc, char *argv[])
{
	struct tracer tracers[MAX_TRACERS];
	int n = 0;
	bool suspend = false;
	bool use_ats_compatibility = true;
	pid_t parent = getppid();

	/* Establish SIGCONT handler as early as lazily possible. */
	(void)signal(SIGCONT, continue_handler);

	openlog("invoker", LOG_PID, LOG_DAEMON);
	config.log = inv_log_syslog;

	static struct option options[] = {
	    { "target", required_argument, 0, 'p' },
	    { "tracer", required_argument, 0, 't' },
	    { "wait", no_argument, 0, 'w' },
	    { "no-ats-compatibility", no_argument, 0, 'n'},
	    { "debug", no_argument, 0, 'd'},
	    { "host", required_argument, 0, 'o'},
	    { "syslog", no_argument, 0, 's'},
	    { "version", no_argument, 0, 'v'},
	    { "help", no_argument, 0, 'h' },
	    { NULL, 0, 0, 0 }
	};

	for (;;) {
		int c;

		c = getopt_long(argc, argv, "p:t:a:sndvh", options, NULL);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'p':
			errno = 0;
			config.target = (pid_t)strtol(optarg, NULL, 10);

			if (config.target == 0 || errno != 0) {
				config.log(LOG_ERR, "invalid "
				    "target pid (%s) specified\n",
				     optarg);
				exit(EXIT_FAILURE);
			}

			break;
		case 't':
			if (n == MAX_TRACERS) {
				config.log(LOG_ERR, "too many tracers "
				    "specified (max is %d)\n",
				    MAX_TRACERS);
				exit(EXIT_FAILURE);
			}

			tracers[n].tracer = strdup(optarg);
			if (tracers[n].tracer == NULL) {
				config.log(LOG_ERR, "failed to allocate "
				    "memory for tracer string: %s\n",
				    strerror(errno));
				exit(EXIT_FAILURE);
			}

			++n;

			break;
		case 'w':
			suspend = true;
			break;
		case 'n':
			use_ats_compatibility = false;
			break;
		case 'd':
			config.log = inv_log_stderr;
			break;
		case 'v':
			fprintf(stdout, "Backtrace Invoker %s\n",
			    AUTOCONF_VERSION);
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(stdout);
			break;
		case 'o':
		case 's':
			/*
			 * These options are purposefully ignored. Backtrace
			 * will already extract this information.
			 */
			break;
		case '?':
		default:
			usage(stderr);
			break;
		}
	}

	if (suspend == true) {
		/*
		 * The invoker may be called on its parent. This leaves us in
		 * the following situation:
		 * 1. The invoker may be a child tracing its parent.
		 * 2. Thus, the invoker will likely not be fork-exec'd only
		 *    when it's needed; it must have a mechanism for blocking
		 *    itself for however long is necessary.
		 * 3. The simplest mechanism is a SIGSTOP/SIGCONT.
		 */
#if defined(__linux__) && defined(PR_SET_PDEATHSIG)
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
			config.log(LOG_ERR, "failed to set death signal: %s\n",
			    strerror(errno));
		}
#endif /* __linux__ && PR_SET_PDEATHSIG */

		/* Raise signal only if continue signal wasn't received. */
		if (continued == 0)
			raise(SIGSTOP);
	}

	/*
	 * It is possible to have been woken up after the parent process
	 * has died. In this case, it is pointless to trace the parent.
	 */
	if (getppid() != parent)
		return 0;

	if (config.target == 0) {
		config.target = getppid();
	}

	if (n < MAX_TRACERS) {
		/* Handle any tracers specified in the envar INVOKER_TRACER. */
		tracers[n].tracer = getenv("INVOKER_TRACER");
		if (tracers[n].tracer != NULL) {
			tracers[n].tracer = strdup(tracers[n].tracer);
			if (tracers[n].tracer == NULL) {
				config.log(LOG_ERR, "failed to allocate "
				    "memory for tracer string: %s\n",
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
			++n;
		}
	}

	/* Default tracer */
	if (n == 0) {
		if (asprintf(&tracers[n].tracer, "%s/bin/ptrace %%p", PREFIX) ==
		    -1) {
			config.log(LOG_ERR, "failed to create string for "
			    "default tracer\n");
			exit(EXIT_FAILURE);
		}
		++n;
	}

	if (parse_tracers(tracers, n) == false) {
		config.log(LOG_ERR, "failed to parse tracers\n");
		exit(EXIT_FAILURE);
	}

	if (use_ats_compatibility == true) {
		ats_compatibility();
	}

	return execute_tracers(tracers, n);
}

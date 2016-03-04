### backtrace-invoker - Tracer Integration with ATS

To install:

- `./configure; make; make install` (For additional options, run `./configure --help`)

To uninstall:

- `make uninstall`

`backtrace-invoker` is a binary which will execute potentially multiple tracing
programs on a target process (or the parent process, if no target is specified).
It is meant to be a drop-in replacement for current crash logging processes
(e.g. `traffic_crashlog`) while providing the ability to run the replaced tracing
process in addition to the new one (e.g. `backtrace-ptrace`).

There are two options for integration:

- Modify `proxy.config.crash_log_helper` to point to the installation path for
`backtrace-invoker`.
- Replace `traffic_crashlog` binary in the configured location with the invoker
binary (keep the `traffic_crashlog` name)

All options currently used by `ATS` (`--syslog`, `--wait`, `--host`) are accepted,
though `--syslog` and `--host` are ignored.

Messages are logged to syslog (`LOG_DAEMON`) by default (`stderr` logging can be
enabled with `-d/--debug`).

Hostname is not used by the backtrace-ptrace tracer. `traffic_crashlog` uses it
to determine whether to read ucontext and siginfo from `stdin`; however,
`traffic_crashlog_helper` writes these to the pipe simply if `__linux__` is defined,
so that is all we check in invoker before reading this data from stdin.

ucontext and siginfo are not used by the `backtrace-ptrace` tracer, but these are
read from stdin regardless to keep parity with `traffic_crashlog`. As mentioned
above, this only applies to Linux systems.

A tracer may also be specified via the `INVOKER_TRACER` environment variable.
This is useful if one would like to avoid code changes but the desired tracer
requires specific parameters. For example, one might typically specify an output
directory to `backtrace-ptrace` via `-o <output_directory`.

If no tracer is specified, the backtrace-ptrace tracer will be used by default.
`backtrace-ptrace` is expected to exist in the `INSTALLATION_PREFIX/bin` directory.
The installation prefix defaults to `/opt/backtrace` unless otherwise specified.

Example invocation: `./invoker -p 5923 -t "/opt/backtrace/bin/ptrace %p" --wait`

Help output is reproduced below, but run `backtrace-invoker` with `-h` to see
the latest binary's help.

```
Usage: invoker [<options>]

    -p, --target=<pid>            Target process to trace. If left
                                  unspecified, the parent process will be
                                  traced.

    -t, --tracer=<path args>      Tracer to run against the target process.
                                  If left unspecified, backtrace_ptrace will
                                  be used (from its standard installation
                                  directory [/opt/backtrace/bin]).

                                  A format string to pass into the specified
                                  tracer may be supplied as well.
                                  Supported replacements:
                                      %p: target pid
                                  Multiple tracers may be specified (up to a
                                  maximum of 16), and will be executed in order.
                                  If any of the tracers fail to exit successfully,
                                  subsequent tracers will not be executed.

    -w, --wait                    Suspends the process before invoking the
                                  tracer until receiving a SIGCONT. This
                                  exists for compatibility with ATS Crash
                                  Logger, and may be removed in the future.

    -n,                           Disables Apache Traffic Server compatibility
    --no-ats-compatibility        mode. Certain actions (reading from stdin)
                                  are necessary only to keep parity with ATS
                                  crash logger. This is currently enabled by
                                  default.

    -d, --debug                   Prints log messages to stderr instead of
                                  syslog.

    -v, --version                 Prints invoker version.

    -h, --help                    Prints this help message.
```

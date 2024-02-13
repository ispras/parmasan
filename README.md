# parmasan - a parallel make sanitizer

This toolset can be used to automatically detect possible race conditions in makefiles. It consists of multiple
executables:

- parmasan daemon
- tracer
- patched remake (hosted on a [separate repository](https://github.com/ispras/parmasan-remake), should be cloned
  separately)

## Prerequisites

- CMake
- A C++ Compiler

## Building

```bash
git clone https://github.com/ispras/parmasan
mkdir parmasan/build
cmake -S parmasan -B parmasan/build
make -C parmasan/build

# Paths to binaries are referred below as follows:
export PARMASAN_BIN="$(pwd)/parmasan/build/daemon/parmasan"
export TRACER_BIN="$(pwd)/parmasan/build/tracer/tracer"
```

**Note:** You should also build the [parmasan-remake](https://github.com/ispras/parmasan-remake) project. It has its own
prerequisites:

- autoconf
- autopoint
- pkg-config
- libreadline-dev

```bash
git clone https://github.com/ispras/parmasan-remake
(cd parmasan-remake && autoreconf -f -i)
(cd parmasan-remake && ./configure --with-make-name=make --disable-posix-spawn)
make -C parmasan-remake/lib
make -C parmasan-remake/libdebugger
make -C parmasan-remake make
export REMAKE_BIN=$(pwd)/parmasan-remake/make
```

## How to use

**TLDR:** To build your project under parmasan, replace your `make` invocation with the following line:

```
$PARMASAN_BIN <parmasan flags...> \
	$TRACER_BIN \
	$REMAKE_BIN <make arguments...>
```

**Note:** Pay attention to escaping backslashes above. This is a single command, not three.

This command will start the parmasan daemon, the tracer process and the make tool inside one another. After the build,
detected races will be located in `parmasan-dump.txt` file in your current working directory.

### Parmasan daemon

```
Usage: parmasan
	[-o | --output OUTPUT]
	[-a | --append]
	[-i[MODE] | --interactive [MODE]]
	[-d | --dump]
	[-r | --read INPUT]
	[-s | --socket SOCKET]
	[-b<BREAKPOINT> | --break=BREAKPOINT]
	[-B<BREAKPOINT> | --break-not=BREAKPOINT]
	[-w<BREAKPOINT> | --watch=BREAKPOINT]
	[-W<BREAKPOINT> | --watch-not=BREAKPOINT]
	[-- COMMAND [ARGS...]]
```

When called without `COMMAND`, parmasan executable starts an interactive shell as a child process, so tracer can be
started manually from there.

**Note:** Don't reset the environment before invoking remake (e.g. if your build command is a script that does something
else before invoking remake). The `tracer` and `remake` executables expect `PARMASAN_DAEMON_SOCK` environment variable
to
be set by parmasan daemon.

#### CLI Flags:

- `-o | --output OUTPUT`:
  Change the output file. Default is `parmasan-dump.txt`.

- `-a | --append`
  Append to the output file instead of overwriting it.

- `-i[MODE] | --interactive [MODE]`
  Enable interactive mode. Mode is either `NONE`, `FAST`, or `SYNC`. Default is `NONE`, implicit value is `SYNC`. Read
  more in [Using breakpoints](#using-breakpoints) section.

- `-d | --dump`
  Dump the build log instead of doing the race condition search. Read more in
  [Recording and replaying a build](#recording-and-replaying-a-build)

- `-r | --read INPUT`
  Read the build log as an input. Read more in [Recording and replaying a build](#recording-and-replaying-a-build)

- `-s | --socket SOCKET`
  Change the path for internally used unix socket. Leading `$` can be added to use socket in abstract namespace.
  Default is `$parmasan-socket`

- `-b<BREAKPOINT> | --break=BREAKPOINT`
  Break on certain events. This flag can only be used if interactive mode is not `NONE`. Read more in
  [Using breakpoints](#using-breakpoints) section.

- `-B<BREAKPOINT> | --break-not=BREAKPOINT`
  Do not break on certain events. This flag can only be used if interactive mode is not `NONE`. Read more in
  [Using breakpoints](#using-breakpoints) section.

- `-w<BREAKPOINT> | --watch=BREAKPOINT`
  Log certain events to the output file. Read more in [Using breakpoints](#using-breakpoints) section.

- `-W<BREAKPOINT> | --watch-not=BREAKPOINT`
  Do not log certain events to the output file. Read more in [Using breakpoints](#using-breakpoints) section.

### Tracer

The tracer executable only takes a command to be traced.

```
Usage: tracer COMMAND [ARGS...]
```

**Note:** tracer should be launched as a child process of parmasan daemon, either through specifying it as a `COMMAND`
or by using its interactive shell. It won't launch if `PARMASAN_DAEMON_SOCK` environment variable is not present.

**Note:** tracer uses `ptrace` syscall to intercept system calls of the build processes. This can cause trouble under
docker or some restricted/old kernels. Make sure it's available on your system.

**Note**: `tracer` will not bring an interactive shell if `COMMAND` is not specified. It's a required argument.

### Remake

The patched version of `remake` have new `parmasan-strategy` flag:

```
remake <...> --parmasan-strategy=[env|require|disable]
```

- **`env`:** (_default_) - use the parmasan daemon if the `PARMASAN_DAEMON_SOCK` environment variable is present.
- **`require`:** Always use the parmasan daemon. Stop the build if `PARMASAN_DAEMON_SOCK` is not present.
- **`disable`:** Ignore `PARMASAN_DAEMON_SOCK` and act as unpatched remake.

## Recording and replaying a build

Replaying a build can be much quicker than restarting the entire build process from scratch.

To record a build, the `-d` or `--dump` flag is used. It tells parmasan to dump the build log in the output file
instead of doing its usual duty of detecting the race conditions.

```
$PARMASAN_BIN --dump --output build-log.txt $TRACER_BIN ...
```

To use a build log as an input for parmasan daemon, use `-r` or `--read` flag.

```
$PARMASAN_BIN --read build-log.txt --output races.txt
```

When `--read` flag is used, parmasan will not launch any child processes.

## Using breakpoints

To use breakpoints, interactive mode should be enabled via `--interactive` or `-i` options:

- `--interactive=none` or `-inone`: (_default_) - interactive mode is disabled
- `--interactive=fast` or `-ifast`: interactive mode is enabled without enforcing synchronous event handling. The build
  process is paused using `SIGSTOP`, which can induce a slight delay between breakpoint hit and actual process
  suspension.
- `--interactive[=sync]` or `-i[sync]`: interactive mode is enabled, event handling is synchronous. The build process
  will be stopped immediately upon hitting a breakpoint at a cost of slight performance penalty.

By default, with `--interactive` flag specified, parmasan will stop the build and bring an interactive console for each
race listed in `parmasan-dump.txt`.

Only races outside of `/dev/` directory are reported to ignore false positives on devices such as `/dev/tty`
and `/dev/null`. This can be overridden by `--break` and `--watch` options.

### `--break` and `--watch` options

`--break` (or `-b`) option configures breakpoints, while `--watch` (`-w`) changes events that will be logged in
the `parmasan-dump.txt`.

The syntax for these options is identical:

```
--[break|watch]='<events>:<glob>'
```

`<events>` is a set of one-char events that should trigger the breakpoint:

- `r` and `w` stands for **read** and **write**. Both of these are triggered on **read-write** access.
- `a` is triggered only for **read-write** access.
- `u` corresponds to **unlink**.
- `R` is triggered when race is detected on particular file.

**Note**: If the glob starts with `/`, it will trigger on any path matching the pattern. Otherwise, your current working
directory is used as a base path for the glob.

**Note**: Be sure to wrap your filter in single quotes (`'`) to avoid shell globbing.

#### Examples

- `--break='rwauR:/*.txt'`: pause the build on any event on any file ending with `.txt`.
- `--watch='w:build/librace.a'`: Log all write operations to `build/librace.a` under your current working directory.

**Hint**: Multiple `--break` and `--watch` options can be used in the same parmasan invocation along
with  `--watch-not` (`-W`) and `--break-not` (`-B`) options to fine-tune the triggering set of events. The filters are
applied in the same order as they appear in the argument list. They can also be configured for each type of event
separately.

**Example:**

```
$PARMASAN_BIN ... \
	--break='rw:*/source1.*' \
	--break='rw:*/source2.*' \
	--break-not='rw:*.cpp'
```

The above example will trigger on read and write events
on `src/source1.o`, `src/source2.o`, `src/source1.h`, `src/source2.h`, but not on `src/source1.cpp`
and `src/source2.cpp`.

### Debug console commands

The parmasan debug console has the following commands:

- `help` - Print the help message
- `quit` - Terminate the interrupted build
- `continue` - Continue the interrupted build upon next breakpoint
- `pidup` - Print the information about the specified process and its ancestors
- `piddown` - Print information about the specified process and its descendants
- `pid` - Print full information of the specific process
- `status` - Print the stop reason
- `break` - Break on event(s)
- `break-not` - Do not break on event(s)
- `watch` - Log event(s)
- `watch-not` - Do not log event(s)
- `targets` - Inspect makefile targets

If command requires a process as an argument, it can be specified in several different ways:

- `-p <pid>` - Refers to the alive process with specified pid.
- `-p <pid>.<epoch>` - If several processes happened to share the same pid along the build, they are going to have
  different __pid epoch__. It can be specified after a dot. This notation is widely used in the parmasan interface.
- `-l` and `-r` - Refers to the process that performed the **left** or **right** access (in a context of detected race
  condition).
- `-a` refers to the root process (the tracer process).

**Note:** A dead process cannot be referred with `-p <pid>`. It only works for alive processes. Use `-p <pid>.<epoch>`
or context-specific flags.

The `-m` option can be used for `pidup` and `piddown` commands to only list `make` processes.

The `-f <GLOB>` option can be used for `targets` command to filter targets by their names.

`break[-not]` and `watch[-not]` commands take a breakpoint as an argument. They have the same syntax as the
corresponding [command line arguments](#-break-and-watch-options).

#### Examples

- `piddown -a -d 5`: Print the process tree from the root process with depth of 5.
- `break 'rwu:/*/log.txt'`: Break on the next read, write, or unlink operation on any file named `log.txt`.
- `pidup -l`: Print the parent list for the process that performed the left access in a context of detected race
  condition.
- `targets -n 20 -f *.h -p 5583.0`: Print first 20 target names ending with `.h` of the first make process with pid
  5583.

**Hint:** The command can be specified by its prefix, as long as it's unambiguous. For example, `q` can be typed
for `quit`,
`c` for `continue`, etc.

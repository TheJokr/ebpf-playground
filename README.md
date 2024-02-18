# ebpf-playground
[![Go version](https://img.shields.io/badge/v1.21-555?logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT-informational)](#license)

This repository serves to collect eBPF programs and supporting code that I build
to explore, demonstrate, test, and evaluate various features of eBPF in the Linux kernel.
I aim to extensively document my eBPF programs, such that they may also be helpful as
introductions and guides to the landscape of low-level eBPF programming.

The first tool, `observer`, is a tracer for HTTP client requests from Go's `net/http`
stdlib package. It attaches to any (non-stripped) Go binary, *without requiring separate
instrumentation code inside the binary*. The idea originates from distributed tracing
provider [Odigos], and also sits at the core of Grafana Labs' [Beyla] toolchain. Check out
[`probe.c`](observer/bpf/probe.c) to take a look behind the magic.

[Odigos]: https://news.ycombinator.com/item?id=34442603
[Beyla]: https://grafana.com/blog/2023/09/13/grafana-beyla-open-source-ebpf-auto-instrumentation/

## Usage
Since compiled eBPF objects are checked into the repository, building any of the applications
requires just a Linux host with an up-to-date Go toolchain (v1.21+) and the ability to set
[file capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html). If you can
`sudo`, you are probably all set. For ease-of-use there is also a devcontainer setup included
in this repo, which fulfills all requirements.

The Makefile contains all necessary commands for an `observer` demonstration:
```shell
# By default, the Makefile builds the observer tool. File capabilities are set
# as part of the build, which uses sudo and thus might ask for your password.
# The tool is built under /tmp to ensure filesystem support for capabilities.
$ make
# This next commands starts a fake service mesh based on nicholasjackson/fake-service
# to give observer something to attach to.
$ make run-mesh
# Finally, in a separate shell, we can start the observer. This simply executes
# /tmp/observer /path/to/fake-service. You can attach to any Go app by exchanging
# the path argument (provided you didn't strip its symbol table).
$ make observe-mesh
# When you open http://localhost:8080/ with your browser, curl, or some other HTTP client,
# you will see all the background requests in the service mesh logged by the observer.
```

### Compiling eBPF Programs
If you want to hack on an eBPF program, you will need a C-to-eBPF toolchain in addition
to the requirements listed above. clang/LLVM is most commonly used for this task, but a
few additional dependencies are also required. I recommend either using the included
devcontainer directly, or checking out its [Dockerfile](.devcontainer/Dockerfile).

## License
All code in this repository is licensed under the [MIT license](LICENSE) and may freely
be copied and re-used in accordance with that license. eBPF code and related header files
(everything below a `bpf/` subdirectory) is additionally licensed under the
[GNU GPLv2](https://www.gnu.org/licenses/gpl-2.0.html) at your option.

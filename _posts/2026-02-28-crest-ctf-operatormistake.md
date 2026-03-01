---
title: CREST CTF - operator_mistake
date: 2026-02-28 19:00:00 +0530
categories:
  - CTF
  - Crest CTF
tags:
  - binary
  - rev
---

# Overview

This one is the opposite of `ghost_mantis_scanner`: the binary looks like it
might hide something deeper, but the intended solve is just to pay attention to
the environment variable exposed by `strings` and confirm the branch in
disassembly.

Flag:

```text
CREST{0p-m4nti$-07-0228-4ttrib}
```

## Solve plan

Because the challenge felt intentionally easy, I kept the workflow simple:

1. run the binary once normally
2. check `strings`
3. try the obvious environment variable
4. confirm the control flow in `objdump`

## 1. Baseline run

```bash
$ ./rev/operator_mistake
Operator module initialized.
Telemetry active.
No debugging interface exposed.
```

So the program does not ask for input and just exits after printing a few status
messages.

## 2. `strings` gives away the input surface

```bash
$ strings -n 6 rev/operator_mistake | head -n 24
/lib64/ld-linux-x86-64.so.2
__stack_chk_fail
ptrace
getpid
stdout
__libc_start_main
__cxa_finalize
getenv
libc.so.6
GLIBC_2.4
GLIBC_2.34
GLIBC_2.2.5
Operator module initialized.
Telemetry active.
GM_DEBUG
No debugging interface exposed.
```

The interesting part is obvious:

```text
GM_DEBUG
```

At that point the most reasonable test is to set it and rerun the binary.

## 3. My solve

```bash
$ GM_DEBUG=1 ./rev/operator_mistake
Operator module initialized.
Telemetry active.
No debugging interface exposed.
CREST{0p-m4nti$-07-0228-4ttrib}
```

That is the flag already.

## Final flag

```text
CREST{0p-m4nti$-07-0228-4ttrib}
```

i think this was operator's mistake so this challenge was taken down :)
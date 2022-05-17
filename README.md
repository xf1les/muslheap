# muslheap

**muslheap** is a simple [GDB](https://www.gnu.org/software/gdb/) plug-in for inspecting mallocng.

This plugin provides additional GDB commands to explore mallocng global states and internal data structures (slot, group, meta and so on).

## What is mallocng

**mallocng** is a new dynamic memory allocator in [musl libc](https://musl.libc.org/) v1.2.1+, aiming to provide strong hardening against common memory usage errors such as overflows, double-free, and use-after-free.

<details markdown="1">

<summary markdown="1">The High-level design</summary>

(from [mallocng-draft](https://github.com/richfelker/mallocng-draft#high-level-design))

1. Memory organized dynamically into small slab-style groups of up to 32 identical-size allocation units with status controlled by bitmasks.

2. Utilize a mix of in-band and out-of-band metadata to isolate sensitive state from regions easily accessible through out-of-bounds writes.

3. Smalle allocations come from groups of one of 48 size classes, while large allocations are made individually by mmap treated as special one-member groups.

4. The first 8 size classes are spaced linearly up to 128, then roughly geometrically with four steps per doubling adjusted to divide powers of two with minimal remainder (waste).

5. Base allocation granularity and alignment is 16 bytes.

</details>

## Installation

`echo "source /path/to/muslheap.py" >> ~/.gdbinit`

**Requirements:**
 - **Python 2.7.15+** (Python 3.5.2+ is recommended)
 - **GDB 7.11.1+** with [python support](https://sourceware.org/gdb/onlinedocs/gdb/Python.html)
 - **musl libc 1.2.1+** with debug symbols

(Older versions of Python / GDB are untested and may not work as expected)

musl libc debug symbols can be installed from system repository:  
  - **Ubuntu:** [Enable dbgsym repository](https://wiki.ubuntu.com/Debug%20Symbol%20Packages#Getting_-dbgsym.ddeb_packages), then `apt install musl-dbgsym`
  - **Alpine Linux:** `apk add musl-dbg`

## Features

- `mchunkinfo`: Examine a mallocng-allocated memory (slot)

- `mfindslot`: Find out the slot where the given memory is inside

- `mheapinfo`: Display mallocng allocator internal information

- `mmagic`: Display the location of important functions and sensitive variables in musl libc

## Getting started

### 1. Explore memory

* **`mchunkinfo`** is used to inspect a mallocng-allocated memory (slot). The memory address given must be the starting address of user data area (`user_data`) inside an *in-use* slot. **In most cases, it should be a pointer returned from `malloc()`.**

![a normal memory](https://user-images.githubusercontent.com/55195054/168587403-d8cfb649-048a-4d34-8df9-34bb890c3240.jpg)

`mchunkinfo` can validate the parsed data (such as in-band meta, meta and overflow bytes) and highlight if one of these validations failed.

![This memory has been overflowed](https://user-images.githubusercontent.com/55195054/168587617-2e5d0bc1-992f-4877-9951-2eed9d607a6c.png)

![This memory has a highly corrupted meta object](https://user-images.githubusercontent.com/55195054/168587712-9a7926fa-3472-4290-a71d-d4f9f9325ec2.png)

* **`mfindslot`** is used to find out which slot the given memory address is inside. It's useful to inspect **a freed slot** (which has no `user_data`) or if you don't know the location of slot's `user_data`.

![](https://user-images.githubusercontent.com/55195054/168610595-0836984a-b3e4-47fa-ac51-f44269ba5896.png)

If the slot is in-use, `mfindslot` will try to determine the address of `user_data`.

![](https://user-images.githubusercontent.com/55195054/168614585-20dd04f7-3db6-476e-9f18-20197c28437f.png)

### 2. Display allocator status

- **`mheapinfo`**: Display mallocng allocator internal information (such as secret cookie, `active` chains and `meta_area` chain). These data are parsed from `__malloc_ctx`.

- **`mmagic`**: Display the location (in offset) of important functions (such as [`system`](https://man7.org/linux/man-pages/man3/system.3.html)) and sensitive variables (such as `__stack_chk_guard`) in musl libc. Useful for binary exploitation and [CTF](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)) games. 

![](https://user-images.githubusercontent.com/55195054/168616739-54489dd0-7831-46c7-a128-7476a0a7c4e4.png)

## TODO

- [ ] Detailed documentation for mallocng
- [ ] Check compatibility on 32-bit and non-x86/x64 (aarch64, MIPS etc.) architecture
- [ ] Add command to display slot usage (`usage_by_classes`) and bounce status (`is_bouncing`) of a sizeclass

## Reference

* [mallocng source code](http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng?h=v1.2.2)
* [mallocng-draft](https://github.com/richfelker/mallocng-draft)

## License

The MIT License (MIT)


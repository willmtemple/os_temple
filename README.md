# The Other Temple OS

## Running

```
$ cd vmm_test_bin
$ cargo krun
```

If debug mode doesn't work then try running with `--release` as it produces a simpler binary.

## Architecture

- `vmm` is a crate that implements a virtual machine manager. It is programmed to load a relocatable ELF binary into
  a KVM virtual machine. It also supports a virtual display. Essentially, it implements a "bootloader" for freestanding
  ELF binaries so that you don't have to worry about packing your binary into a disk image or whatever. You can just
  pass the path to the ELF as an argument to `vmm`.

  Currently, the page table identity maps 0x0 (inclusive) to 0x1000000 (exclusive) using big (2MiB) pages and
  0xfee0000 - 0xfee1000 (APIC registers).

  The level 4 page table is located at address 0x1000.

  The local APIC is mapped to 0xfee00000 (though you can use the apic MSR to get this address just as well).

  Kernel ELF code is mapped beginning at 0x200000 (2MiB) and the `_start` function is executed first. No arguments are
  passed to the function.

  The framebuffer for the display is mapped to 0x300000 and is 1920x1080x4 bytes long. It will probably be B8G8R8A8
  pixel format but it actually just uses whatever Vulkan decides to give you for your swapchain.

  The stack pointer is initialized to the end of mapped memory (0x1000000).

## Requirements

- Linux with KVM enabled (requires virtualization extensions)
- Vulkan (install vulkan-icd-loader or whatever it is and make sure your graphics support it)

Hypervisors other than KVM are not supported, but support could probably be added without a _whole_ lot of fuss.

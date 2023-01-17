# The Other Temple OS

## Running

```
$ cd vmm_test_bin
$ cargo krun
```

If debug mode doesn't work then try running with `--release` as it produces a simpler binary.

## Architecture

- `vmm` is a crate that implements a virtual machine manager. It is programmed to load a

## Requirements

- Linux with KVM enabled (requires virtualization extensions)
- Vulkan (install vulkan-icd-loader or whatever it is and make sure your graphics support it)

Hypervisors other than KVM are not supported, but support could probably be added without too much fuss.

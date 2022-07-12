# Development with Cargo

Although this library are built by Android build system officially, we can also
build and test the library by cargo.

## Building `packets` package
This package depends on `bluetooth_packetgen` and thus simply using
`cargo build` will fail. Follow the steps below before using cargo.

1. Enter Android environment by `source build/make/rbesetup.sh; lunch <target>`
2. Run `m -j32 bluetooth_packetgen` to compile `bluetooth_packetgen` c++ binary.

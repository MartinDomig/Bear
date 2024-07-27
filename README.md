# Fuzzy Bear

Fuzzy Bear is a fuzzing library for testing applications that offer any form of protocol communication on the network. It is designed to be simple to use and still be powerful enough to test a wide range of communication protocols, including binary and custom protocols.

## License

Fuzzy Bear is licensed under the GPL license (version 3). See the [LICENSE](LICENSE) file for more information.

## Building

Fuzzy Bear is written in C, using the glib library and the meson build system.

To get a working environment, you either can use the included Dockerfile, or install the dependencies manually. They aren't many, just take a look at the Dockerfile if you are unsure.

Setup a build environment using docker:
```sh
docker compose up -d
docker attach bear
```

If you don't like docker (can't blame you), install the dependencies manually (they aren't many). Just take a look at the Dockerfile.

To build:

```sh
meson setup build
meson compile -C build
```
To install:
```sh
meson install -C build
```
Consult the included Dockerfile if you can't figure out a missing dependency, I used that for working on the project.

## Usage

Fuzzy Bear is a library, so you will need to write your own code to use it. The library is designed to be simple to use, and the included examples should be enough to get you started even if you're not familiar with C or glib. Take a look in the [audit](audit) directory for examples.

## Credits

Fuzzy Bear was created by Martin Domig, inspired by the [spike framework](https://gitlab.com/kalilinux/packages/spike) that comes with Kali Linux. Spike is great, but I needed something more flexible and easier to use, and not tied to automake. So I created Fuzzy Bear.

It is not a fork of spike, but it is heavily inspired by it. Some code snippets are taken from spike (especially string generation), but most of the code is written from scratch.
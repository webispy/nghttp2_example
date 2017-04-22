# nghttp2 example
http/2 c client example

## Build

### Install build dependency packages
* Ubuntu
```sh
apt install libglib2.0-dev libnghttp2-dev libssl-dev libhttp-parser-dev cmake
```
* Fedora
```sh
dnf install glib2-devel libnghttp2-devel openssl-devel http-parser-devel cmake
```

### Build
```sh
mkdir build
cd build
cmake ..
make
```

## Test
```sh
./client https://nghttp2.org/
```

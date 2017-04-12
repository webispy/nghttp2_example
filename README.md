# nghttp2 example
http/2 c client example

## Build

### Install build dependency packages
```sh
apt install libnghttp2-dev libssl-dev cmake
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

[![Coverity Scan Build Status](https://scan.coverity.com/projects/12579/badge.svg)](https://scan.coverity.com/projects/webispy-nghttp2_example)
[![Build Status](https://travis-ci.org/webispy/nghttp2_example.svg?branch=master)](https://travis-ci.org/webispy/nghttp2_example)

# nghttp2 example
http/2 c client example

## Build

### Install build dependency packages
* Ubuntu
```sh
apt install libglib2.0-dev libnghttp2-dev libssl-dev libhttp-parser-dev cmake libasound2-dev
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

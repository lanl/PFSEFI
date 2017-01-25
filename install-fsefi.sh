#!/bin/bash
# Instructions for installing FSEFI 1.0 on Ubuntu 12.04 Linux 64-bit

# Things that require root access are preceded with "sudo".

# FSEFI is based on QEMU. It's useful to have a vanilla QEMU for testing
# and image development:
sudo apt-get -y install qemu #optional

# You may need to install some packages required for libSDL
sudo apt-get -y install build-essential xorg-dev libudev-dev libts-dev libgl1-mesa-dev libglu1-mesa-dev libasound2-dev libpulse-dev libopenal-dev libogg-dev libvorbis-dev libaudiofile-dev libpng12-dev libfreetype6-dev libusb-dev libdbus-1-dev zlib1g-dev libdirectfb-dev

# Install the libSDL
sudo apt-get -y install libsdl*

# Install bfd package
sudo apt-get -y install libbfd-dev

sudo apt-get -y install libssl-dev

# Build the sleuthkit-2.04
(cd shared/sleuthkit && make)
(cd shared && ln -s sleuthkit-2.04 sleuthkit)

# Build the llconf
(cd shared/llconf && CFLAGS="-fPIC" ./configure --prefix=$(pwd)/install)
(cd shared/llconf && make)
(cd shared/llconf && make install)
(cd shared && ln -s llconf-0.4.6 llconf) 

# Build FSEFI
./configure --target-list=i386-softmmu --proj-name=tracecap --prefix=$(pwd)/install --disable-gcc-check --cc=gcc-4.6
make clean
make 


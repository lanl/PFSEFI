from ubuntu:12.04
MAINTAINER qguan "qguan@lanl.gov"

# Starts here
#
RUN apt-get -y update
RUN apt-get -y install\
  autoconf\
  build-essential\
  cmake\
  ctags\
  curl\
  gfortran\
  git\
  libopenmpi-dev\
  openmpi-bin\
  openmpi-doc\
  openssh-server\
  vim\
  wget

RUN apt-get -y install sshpass

RUN apt-get -y install\
  qemu\
  xorg-dev\
  libudev-dev\
  libts-dev\
  libgl1-mesa-dev\
  libglu1-mesa-dev\
  libasound2-dev\
  libpulse-dev\
  libopenal-dev\ 
  libogg-dev\
  libvorbis-dev\
  libaudiofile-dev\
  libpng12-dev\
  libfreetype6-dev\
  libusb-dev\
  libdbus-1-dev\
  zlib1g-dev\
  libdirectfb-dev\
  openssl\
  libssl-dev\
  libsdl-dev\
  libbfd-dev

# X11 Window
RUN apt-get -y install\
      xorg\
      openbox
# Add user
RUN groupadd -r user && useradd -r -m -g user user
RUN mkdir /home/user/codes
# git lfs
WORKDIR /home/user
RUN wget https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh
RUN bash script.deb.sh
RUN rm script.deb.sh
RUN apt-get -y install git-lfs

# Download PFSEFI to local directory
WORKDIR /home/user
RUN git clone https://github.com/losalamos/PFSEFI.git
WORKDIR /home/user/PFSEFI
RUN git lfs install
RUN git lfs track "*.patch"
RUN git lfs fetch
RUN git lfs checkout 

# Download the original temu
WORKDIR /home/user
RUN wget http://bitblaze.cs.berkeley.edu/release/temu-1.0/temu-1.0.tar.gz
RUN tar zxvf temu-1.0.tar.gz
WORKDIR /home/user/temu-1.0
RUN patch -p1 < /home/user/PFSEFI/fsefi.patch
RUN cp -r ./* /home/user/codes/
RUN rm -r /home/user/temu-1.0

# Build FSEFI
WORKDIR /home/user/codes
RUN ./configure --target-list=i386-softmmu --proj-name=tracecap --prefix=$(pwd)/install --disable-gcc-check --cc=gcc-4.6
RUN make clean; make




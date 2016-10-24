# Parallel Fine-grained Soft Error Fault Injector (P-FSEFI)

P-FSEFI builds upon F-SEFI, the sequential fault injection tool and used to study a number of applications. This extension adds support for injecting faults into parallel applications, something vitally important to advance
the original tool to be useful to the high performance computing
(HPC) and supercomputing field. P-FSEFI allows
multiple F-SEFI instances to be connected. They can be on the
same physical host or multiple, different physical hosts. A parallel
program, such as an MPI program, is then run within this collection
of F-SEFI instances. This program communicates outside of
theVMand into other F-SEFIVMinstances as it passes data to perform
a parallel calculation. This capability is what makes P-FSEFI unique and extensible to allow one to emulate a parallel process
running on a virtual cluster. 

# Attribution

Researchers who use the P-FSEFI for scientific research are asked to cite
the papers by Qiang Guan listed below.

1. Qiang Guan, Nathan BeBardeleben, Panruo Wu, Stephan Eidenbenz,
Sean Blanchard, Laura Monroe, Elisabeth Baseman, and Li Tan, "Design, Use and Evaluation of P-FSEFI: A Parallel Soft
Error Fault Injection Framework for Emulating Soft Errors
in Parallel Applications" in Ninth EAI International Conference on Simulation Tools and Techniques (SIMTOOLS), 2016.

2. Qiang Guan, Nathan Debardeleben, Sean Blanchard, Song Fu, "f-sefi: A fine-grained soft error fault injection tool for profiling application vulnerability," Proc. of 2014 IEEE 28th International Parallel and Distributed Processing Symposium (IPDPS), 2014.
http://ieeexplore.ieee.org/xpls/abs_all.jsp?arnumber=6877352&tag=1

3. Nathan DeBardeleben, Sean Blanchard, Qiang Guan, Ziming Zhang, Song Fu, "Experimental framework for injecting logic errors in a virtual machine to profile applications for soft error resilience", In Proc. of Euro-Par'11 Proceedings of the 2011 international conference on Parallel Processing - Volume 2
Pages 282-291, 2011.
http://dl.acm.org/citation.cfm?id=2238472


# Getting the Code

P-FSEFI is built upon the QEMU and TEMU, the dynamic analysis tool. You have to first check out the TEMU source code and apply the patch and then copy the new tracecap folder under the TEMU home directory. You must install git lfs in your local system pelase check https://git-lfs.github.com 

# Install git lfs
     $ cd /home/user/
     $ wget https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh
     $ bash script.deb.sh
     $ rm script.deb.sh
     $ apt-get -y install git-lfs

# Download PFSEFI and patch the code
     $ cd /home/user   ## assume your user name is user
     $ git clone https://github.com/losalamos/PFSEFI.git
     $ cd /home/user/PFSEFI
     $ git lfs install
     $ git lfs track "*.patch"
     $ git lfs fetch
     $ git lfs checkout
     $ mkdir /home/user/pfsefi
     $ cd /home/user
     $ wget http://bitblaze.cs.berkeley.edu/release/temu-1.0/temu-1.0.tar.gz
     $ tar zxvf temu-1.0.tar.gz
     $ cd temu-1.0
     $ git clone https://github.com/losalamos/PFSEFI.git
     $ patch  -p1 < PFSEFI/fsefi.patch
     $ cp -r ./* /home/user/pfsefi/
     $ cd ..
     $ rm -r /home/user/temu-1.0

These commands download source code and patch P-FSEFI functions. For more information about TEMU please check 
[here](http://bitblaze.cs.berkeley.edu/temu.html).

# Requirements

P-FSEFI has been fully tested on 64-bits Ubuntu 12.04 system. And P-FSEFI only support 32-bits Linux system as the guest.

# Build Instructions

To configure and build, do the following from the top-level source directory:
  
    % ./configure --target-list=i386-softmmu --proj-name=tracecap --prefix=$(pwd)/install --disable-gcc-check 
    % make clean 
    % make 

# Docker Support

P-SEFI supports Docker container. You can either use the Dockerfile to build the conatainer image.

    % docker build -t pfsefi .
    
You can also directly pull the docker container image from dockerhub

    % docker pull guanxyz/pfsefi
    
The container can be started by 

    % docker run --net=host -it guanxyz/pfsefi /bin/bash

# Release

This software has been approved for open source release and has been assigned **LA-CC-16-004**.

# Mail List and Contact

For bugs and problems report, suggestions and other general questions regarding the PFSEFI project, Please subscribe to the [fsefi-users mailing list](https://groups.google.com/forum/#!forum/fsefi-user-discussion)(via Google Groups) and post your quesitons. 


# Copyright
License can be found [here](https://github.com/losalamos/PFSEFI/blob/master/LICENSE)

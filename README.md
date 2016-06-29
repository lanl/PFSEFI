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

P-FSEFI is built upon the QEMU and TEMU, the dynamic analysis tool. You have to first check out the TEMU source code and apply the patch and then copy the new tracecap folder under the TEMU home directory.

    % $ wget http://bitblaze.cs.berkeley.edu/release/temu-1.0/temu-1.0.tar.gz
    % $ tar zxvf temu-1.0.tar.gz
    % $ cd temu-1.0
    % $ git clone https://github.com/losalamos/PFSEFI.git
    % $ patch -R -p1 < PFSEFI/pfsefi.patch
    % $ cp -r PFSEFI/tracecap .

These commands download source code and patch P-FSEFI functions. For more information about TEMU please check 
[here](http://bitblaze.cs.berkeley.edu/temu.html).

# Requirements

P-FSEFI has been fully tested on 64-bits Ubuntu 12.04 system. And P-FSEFI only support 32-bits Linux system as the guest.

# Build Instructions

To configure and build, do the following from the top-level source directory:
  
    % ./configure --target-list=i386-softmmu --proj-name=tracecap --prefix=$(pwd)/install --disable-gcc-check 
    % make clean 
    % make 

# Release

This software has been approved for open source release and has been assigned **LA-CC-16-004**.

# Copyright
Copyright (c) 2016, Los Alamos National Security, LLC
All rights reserved.
Copyright 2016. Los Alamos National Security, LLC. This software was produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos National Laboratory (LANL), which is operated by Los Alamos National Security, LLC for the U.S. Department of Energy. The U.S. Government has rights to use, reproduce, and distribute this software.  NEITHER THE GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  If software is modified to produce derivative works, such modified software should be clearly marked, so as not to confuse it with the version available from LANL.
 
Additionally, redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1.      Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. 
2.      Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. 
3.      Neither the name of Los Alamos National Security, LLC, Los Alamos National Laboratory, LANL, the U.S. Government, nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission. 
THIS SOFTWARE IS PROVIDED BY LOS ALAMOS NATIONAL SECURITY, LLC AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL LOS ALAMOS NATIONAL SECURITY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

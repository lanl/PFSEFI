cd /home/resilience/fsefi/TEMU_HPL1
exec qemu-img create -f qcow -o backing_file=/home/pwu/myubuntu904.qcow tracecap/test/crash_test.qcow
spawn ./tracecap/fsefi -hda tracecap/test/crash_test.qcow -monitor stdio -k en-us -m 1024


#interact
sleep 120 
send "load_plugin ./tracecap/tracecap.so\r"
#expect "Process foo is registered"
expect "tracecap.so is loaded successfully!$"
for {set i 0} {$i < 10} {incr i 1} {
	send "batch_run -a foo -n 20 -m 1000 -t idivl -r 1\r"
	expect "Process foo is registered"
}

interact

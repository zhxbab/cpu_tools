## make install
#
# edit /etc/rc.d/rc.local:
#
#   insmod /lib/modules/2.6.18-53.1.13.el5/kernel/drivers/usb/misc/usbcom.ko    

default:
	$(MAKE) -C  exe/
	cp exe/cpu_msr .
	$(MAKE) -C  driver/ 
	insmod driver/patch.ko
clean:	
	rmmod  driver/patch.ko	
	$(MAKE) -C  driver/ clean
	$(MAKE) -C  exe/ clean
all:
	$(MAKE) -C  exe/
	cp exe/cpu_msr .
	$(MAKE) -C  driver/ 
	insmod driver/patch.ko
low_mod_name = low_module
hi_mod_name = hi_module
obj-m += $(low_mod_name).o
obj-m += $(hi_mod_name).o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


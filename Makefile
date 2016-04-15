lo_m_name = low_module
hi_m_name = hi_module
rem_dir = "~/sshfsdir/"

obj-m += $(lo_m_name).o
obj-m += $(hi_m_name).o
obj-m += cache_test_m.o

cache_test_m-objs := cache_test_module.o \
					 cache_structure.o \
					 hashing.o \
					 hpl_entry.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

deploy: all
	cp $(hi_m_name).ko ~/sshfsdir/

cache_test:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
lo_m_name = low_module
hi_m_name = hi_module
rem_dir = "~/sshfsdir/"

obj-m += low_m.o
obj-m += hi_m.o
obj-m += cache_test_m.o


cache-srcs := cache_structure.o \
			  hashing.o \
			  hpl_entry.o


cache_test_m-objs := cache_test_module.o \
					 $(cache-srcs)

low_m-objs := $(lo_m_name).o \
			  tcp_processing.o \
			  $(cache-srcs)

hi_m-objs := $(hi_m_name).o \
			 tcp_processing.o \
			 $(cache-srcs)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

deploy: all
	cp low_m.ko ~/sshfsdir/Coding/
	cp -r ./scripts/capturing_scripts ~/sshfsdir/Coding/

cache_test:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
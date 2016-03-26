lo_m_name = low_module
hi_m_name = hi_module
rem_dir = "~/sshfsdir/"

obj-m += $(lo_m_name).o
obj-m += $(hi_m_name).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

deploy: all
	cp $(hi_m_name).ko ~/sshfsdir/
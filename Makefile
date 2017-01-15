all: roptester

roptester: roptester.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
#	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o roptester roptester.c
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -rdynamic -o roptester roptester.c -ldl
	sudo chown root roptester
	sudo chgrp root roptester
	sudo chmod +s roptester

clean:
	rm roptester

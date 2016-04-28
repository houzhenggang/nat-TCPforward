all:
	gcc -O0 -g3 -Wall -fmessage-length=0 -o nat checksum.c checksum.h nat.c -lnetfilter_queue -lnfnetlink

clean:
	@rm -f nat


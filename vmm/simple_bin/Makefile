CFLAGS = -Wall -Wextra -Werror -Wno-array-bounds -O2

guest64.o: guest.c
	$(CC) $(CFLAGS) -m64 -ffreestanding -fno-pic -c -o $@ $^

guest64.img: guest64.o
	$(LD) -T guest.ld $^ -o $@

%.img.o: %.img
	$(LD) -b binary -r $^ -o $@

payload: payload.ld guest64.img.o
	$(LD) -T $< -o $@

.PHONY: clean
clean:
	$(RM) kvm-hello-world kvm-hello-world.o payload.o guest16.o \
		guest32.o guest32.img guest32.img.o \
		guest64.o guest64.img guest64.img.o
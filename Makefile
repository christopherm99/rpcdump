CFLAGS+= -W -Wextra -Wpedantic -Werror \
         -Wcast-qual -Wconversion -Wformat=2 -Wformat-security -Wnull-dereference -Wstack-protector \
         -Warray-bounds-pointer-arithmetic -Wconditional-uninitialized -Wcomma -Wpointer-arith -Widiomatic-parentheses \
         -Wunreachable-code-aggressive \
         -I/usr/local/include \
         -fstack-protector-strong -fPIE
LDFLAGS+=-L/usr/local/lib
LIBS   +=-l:libtask.a

all: rpcdump

degob.a: degob/degob.go
	cd degob && \
	go build -buildmode=c-archive -o ../degob.a .

rpcdump.o: rpcdump.c
	$(CC) -c -o $@ $^ $(CFLAGS) -Og -g

rpcdump: rpcdump.o degob.a
	$(CC) $^ $(LDFLAGS) -o $@ $(LIBS)

clean:
	rm -f a.out *.core rpcdump rpcdump.o degob.a

.PHONY: all

CC= gcc
CFLAGS= -c -D CL_LINUX
TARGET= build/libcodelock.a

all: $(TARGET)

$(TARGET): build/codelock.o build/codelock_decoders.o build/codelock_keygen.o build/codelock_random.o
	ar rcs $@ $^

build/codelock.o: codelock.c codelock.h
	$(CC) $(CFLAGS) codelock.c -o $@

build/codelock_decoders.o: codelock_decoders.c codelock.h
	$(CC) $(CFLAGS) -c codelock_decoders.c -o $@

build/codelock_keygen.o: codelock_keygen.c codelock.h
	$(CC) $(CFLAGS) codelock_keygen.c -o $@

build/codelock_random.o: codelock_random.c codelock.h
	$(CC) $(CFLAGS) -c codelock_random.c -o $@

clean:
	rm build/*

test: $(TARGET)
	make -C ../test

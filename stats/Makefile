all: dfr-bf-dmt

dfr-bf-dmt: dfr-bf-dmt.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

dfr: dfr.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

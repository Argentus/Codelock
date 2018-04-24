all: dfr-bf-dmt

dfr-bf-dmt: dfr-bf-dmt.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

dfr: dfr.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

dfr-dec-fix: dfr-dec-fix.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

dfr-dec-fall: dfr-dec-fall.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

dfr-dec-dmax: dfr-dec-dmax.c ../src/build/libcodelock.a
		gcc $@.c ../src/build/libcodelock.a -o $@

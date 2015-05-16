Q=@

ifeq (,$(ANDROID_NDK))
ANDROID_NDK=$(HOME)/android-ndk-r8e
$(warning ANDROID_NDK undefined in environment!using default $(ANDROID_NDK) !!!!)
endif
ifeq (,$(ANDROID_API_LEVEL))
ANDROID_API_LEVEL=14
$(warning ANDROID_API_LEVEL undefined in environment! using default level $(ANDROID_API_LEVEL) !!!!)
endif

ARCH=arm
CROSS_COMPILE:=$(ANDROID_NDK)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-
CFLAGS:=--sysroot=$(ANDROID_NDK)/platforms/android-$(ANDROID_API_LEVEL)/arch-arm -fPIC -O2 -Wall -I.

CC:=$(CROSS_COMPILE)gcc
STRIP:=$(CROSS_COMPILE)strip

tools: CFLAGS= -I. -DSTANDALONE_CFG_ENCRYPTER -DSTANDALONE_MODE

tools: CC:=gcc

tools: STRIP:=strip

AES_OBJS:=aes/aeskey2.o aes/aescrypt.o aes/aestab.o aes/aesxam.o
B64_OBJS:=b64/b64.o
OBJS:= $(AES_OBJS) $(B64_OBJS)

LIBFLAGS:=-shared
LIBTARGET:=libtfcrypt.so

%.o: %.c
	@echo "  CC [U]  $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

$(LIBTARGET): $(OBJS)
	@echo "  LIB     $@"
	$(Q)$(CC) $(CFLAGS) $(LIBFLAGS) -o $(LIBTARGET) $(OBJS)
	@echo "  STRIP   $@"
	$(Q)$(STRIP) $@

tfcrypt: $(OBJS) $(LIBTARGET)

aesxam: $(AES_OBJS)
	@echo "Building aesxam"
	$(Q)$(CC) $(CFLAGS) -o tools/$@ $(AES_OBJS)

b64: $(B64_OBJS)
	@echo "Building b64"
	$(Q)$(CC) $(CFLAGS) -o tools/$@ $(B64_OBJS)

tools: clean aesxam b64

default: clean tfcrypt

clean:
	$(Q)rm -rf $(OBJS) $(LIBTARGET) tools/aesxam tools/b64


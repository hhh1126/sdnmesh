APP = zlib
APP_BASE = zlib

export CC=/opt/toolchains//crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26-binutils-2.28.1/usr/bin/arm-buildroot-linux-gnueabi-gcc
export LDFLAGS=
export CFLAGS=


all: 
	cd $(APP); \
	    ./configure --prefix=/home/sdngw-bcm/BYZR_58/targets/96858GWO_0F2W/fs.build
	$(MAKE) -C zlib all

install:
	

clean:
	-make -C $(APP) clean
	-rm -f $(INSTALL_DIR)/lib/$(APP_BASE).so*

distclean: clea
	-rm -rf $(APP)
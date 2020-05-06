all: mapiq_install

mapiq_install:
	$(MAKE) -C mapiq CROSS=$(CROSS) TARGET=$(TARGET) STAGING_DIR=$(STAGING_DIR) PLATFORM=$(PLATFORM) install install_staging

clean: mapiq_clean

mapiq_clean:
	$(MAKE) -C mapiq clean


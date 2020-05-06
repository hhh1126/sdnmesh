all: csm_install

csm_install:
	$(MAKE) -C csm CROSS=$(CROSS) TARGET=$(TARGET) STAGING_DIR=$(STAGING_DIR) PLATFORM=$(PLATFORM) install install_staging

clean: csm_clean

csm_clean:
	$(MAKE) -C csm clean


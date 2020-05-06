SUBDIRS := $(wildcard */.)
clean_SUBDIRS=$(addprefix clean_,$(SUBDIRS))

all: $(SUBDIRS)
clean: $(clean_SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ \
		CROSS=$(CROSS) \
		TARGET="$(TARGET)" \
		PLATFORM=$(PLATFORM) \
		STAGING_DIR=$(STAGING_DIR)

$(clean_SUBDIRS):
	$(MAKE) -C $(patsubst clean_%,%,$@) clean



.PHONY: all $(SUBDIRS)

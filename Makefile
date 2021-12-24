# (c) Copyright 2021 Aaron Kimball

LIBS = i2cparallel LCD-NHD0440 debugger/dbglib
APPS = poetrybot

TAGS_FILE = tags

all: $(LIBS) $(APPS)

install-libs: $(addsuffix .install,$(LIBS))

.PHONY: all clean install-libs tags TAGS

i2cparallel:
	$(MAKE) -C i2cparallel

LCD-NHD0440: i2cparallel i2cparallel.install
	$(MAKE) -C LCD-NHD0440

debugger/dbglib:
	$(MAKE) -C debugger/dbglib

poetrybot: i2cparallel.install LCD-NHD0440.install debugger/dbglib.install
	$(MAKE) -C poetrybot

# For each library in $LIBS, generate a $(LIB).install target.
define LIB_template
$(1).install: $(1)
	$(MAKE) -C $(1) install
endef
$(foreach lib,$(LIBS),$(eval $(call LIB_template,$(lib))))

tags:
	$(CTAGS) -R $(CTAGS_OPTS) --exclude=*/build/* . \
		$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/cores/arduino \
		$(ARDUINO_DATA_DIR)/packages/$(ARDUINO_PACKAGE)/hardware/$(ARCH)/$(ARCH_VER)/variants/$(VARIANT)

TAGS: tags

clean:
	-find . -name build -type d -exec rm -rf {} \;
	-find . -name *.o -delete


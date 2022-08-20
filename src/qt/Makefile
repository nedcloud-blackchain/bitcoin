.PHONY: FORCE
all: FORCE
	$(MAKE) -C .. blackcoin_qt test_blackcoin_qt
clean: FORCE
	$(MAKE) -C .. blackcoin_qt_clean test_blackcoin_qt_clean
check: FORCE
	$(MAKE) -C .. test_blackcoin_qt_check
blackcoin-qt blackcoin-qt.exe: FORCE
	 $(MAKE) -C .. blackcoin_qt
apk: FORCE
	$(MAKE) -C .. blackcoin_qt_apk

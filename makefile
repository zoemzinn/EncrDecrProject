test1:
	clear
	@echo
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "1) Testing STUDENT's Amal against ABOUTABL's KDC+Basim"
	@echo "   Validates   M1.send ,   M2.receive   ,  M3.send  ,  M4.receive  ,  M5.send"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	cp  kdc_aboutablExecutable         kdc/kdc
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto   -Wno-deprecated-declarations
	cp  basim_aboutablExecutable       basim/basim
	gcc wrappers.c     dispatcher.c -o dispatcher
	@echo "Sharing the Master Keys with the KDC"
	@ln  -s ../amal/amalKey.bin   kdc/amalKey.bin
	@ln  -s ../basim/basimKey.bin kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  ABOUTABL's   KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  STUDENT's    Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  ABOUTABL's   Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test2:
	clear
	@echo
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "2) Testing STUDENT's KDC against ABOUTABL's Amal+Basim"
	@echo "   Validates   M1.receive ,   M2.send"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto   -Wno-deprecated-declarations
	cp  amal_aboutablExecutable        amal/amal
	cp  basim_aboutablExecutable       basim/basim
	gcc wrappers.c     dispatcher.c -o dispatcher
	@echo "Sharing the Master Keys with the KDC"
	@ln  -s ../amal/amalKey.bin   kdc/amalKey.bin
	@ln  -s ../basim/basimKey.bin kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  STUDENT's    KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  ABOUTABL's   Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  ABOUTABL's   Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test3:
	clear
	@echo
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "3) Testing STUDENT's Basim against ABOUTABL's KDC+Amal"
	@echo "   Validates    M3.receive  ,  M4.send  ,  M5.receive"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	cp  kdc_aboutablExecutable         kdc/kdc
	cp  amal_aboutablExecutable        amal/amal
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto   -Wno-deprecated-declarations
	gcc wrappers.c     dispatcher.c -o dispatcher
	@echo "Sharing the Master Keys with the KDC"
	@ln  -s ../amal/amalKey.bin   kdc/amalKey.bin
	@ln  -s ../basim/basimKey.bin kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  ABOUTABL's   KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  ABOUTABL's   Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  STUDENT's    Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

test4:
	clear 
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "4) Testing STUDENT's Code all with itself"
	@echo "   Validates   Everything before submission"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto   -Wno-deprecated-declarations
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto   -Wno-deprecated-declarations
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto   -Wno-deprecated-declarations
	gcc wrappers.c     dispatcher.c -o dispatcher
	@echo "Sharing the Master Keys with the KDC"
	@ln  -s ../amal/amalKey.bin   kdc/amalKey.bin
	@ln  -s ../basim/basimKey.bin kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  STUDENT's    KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  STUDENT's    Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  STUDENT's    Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo
	@echo "======  Comparing Log Files to the Expected Logs  ========="
	@echo
	diff -s    kdc/logKDC.txt        expected/expected_logKDC.txt
	@echo
	diff -s    amal/logAmal.txt      expected/expected_logAMAL.txt
	@echo
	diff -s    basim/logBasim.txt    expected/expected_logBASIM.txt
	@echo

clean:
	rm -f dispatcher   
	rm -f kdc/kdc      kdc/logKDC.txt      kdc/amalKey.bin   kdc/basimKey.bin
	rm -f amal/amal    amal/logAmal.txt  
	rm -f basim/basim  basim/logBasim.txt  
	rm -f *.mp4


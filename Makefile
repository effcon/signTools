INCLUDEPATH = ./include
LIB =./lib
SRCS  =./src


genkey:
	gcc  $(SRCS)/generatorKeys.c  -I ./include -L $(LIB)/ -lcrypto -o  ./bin/generatorKey

sign:
	gcc  $(SRCS)/sm2Sign.c  -I ./include -L $(LIB)/ -lcrypto -o  ./bin/sign

verify:
	gcc  $(SRCS)/sm2Verify.c  -I ./include -L $(LIB)/ -lcrypto -o  ./bin/verify


clean:
	rm -rf  ./bin/*

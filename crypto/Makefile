INCLUDEPATH = ../include/
SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))

staticlib: $(OBJS)
	ar -r  ../lib/libcrypto.a  $(OBJS)

$(OBJS): %.o:%.c
	gcc  -c   $< -o $@  -I $(INCLUDEPATH)

clean:
	rm *.o

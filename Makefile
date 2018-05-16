CC=gcc
CCFLAGS= -std=c11 -g -Wall
LIB= -lcrypto
OUT= lab4_elgamal_schnorr
SRCS= el_gamal.c \
	  utils.c
	 # schnorr.c
OBJS=$(SRCS:.c=.o)
all	:	$(OUT)
$(OUT)	:	$(OBJS)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIB)
clean:
	rm -rf *.o 
	rm -rf $(OUT)
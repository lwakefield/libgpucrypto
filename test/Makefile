GPUCRYPTO_DIR = ../

include ../Makefile.in

#gpucrypto config
GPUCRYPTO_LIBDIR = -L../lib/
GPUCRYPTO_INCDIR = -I../
GPYCRYPTO_LIB = -lgpucrypto

LIBDIR = $(OPENSSL_LIBDIR) \
	 $(CUDA_LIBDIR) \
	 $(GPUCRYPTO_LIBDIR)

LIBS =  -lpthread $(CUDA_LIBS) $(OPENSSL_LIB) $(GPYCRYPTO_LIB)

INC += 	$(GPUCRYPTO_INCDIR)

TARGET_DIR = ../bin/
OBJ_DIR = ../objs/
TARGET_FILES = rsa_test aes_test sha_test
TARGETS = $(addprefix $(TARGET_DIR), $(TARGET_FILES))
OBJS = $(addprefix $(OBJ_DIR), $(addsuffix .o, $(TARGET_FILES))) $(OBJ_DIR)common.o

all: $(TARGETS)

$(TARGET_DIR):
	mkdir $(TARGET_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(TARGET_DIR)% : $(OBJ_DIR)%.o |$(TARGET_DIR) $(OBJ_DIR) ../lib/libgpucrypto.a $(OBJ_DIR)common.o
	$(CC) -o $@ $< $(CFLAGS) $(LIBS) $(LIBDIR) $(OBJ_DIR)common.o

$(OBJ_DIR)%.o : %.cc
	$(CC) $(CFLAGS) $(INC) $(NVINC) -c $< -o $@

.PHONY : clean
clean:
	rm -f $(TARGETS) $(OBJS)

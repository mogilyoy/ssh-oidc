GO = go
CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -Iinclude -I/usr/local/include
LDFLAGS = -lcurl

NSS_TARGET = libnss_oslogin.so
NSS_SRCS = ncc/ncc_oslogin.cc ncc/oslogin_utils.cc
NSS_OBJS = $(NSS_SRCS:.cc=.o)

.PHONY: all qwe nss clean

all: qwe

qwe:
	$(GO) build -o qwe ./cmd/qwe

nss: $(NSS_TARGET)

$(NSS_TARGET): $(NSS_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	rm -f qwe $(NSS_OBJS) $(NSS_TARGET)
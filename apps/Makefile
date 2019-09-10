CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Wextra
LDFLAGS ?=
CFLAGS += 

BIN := template-test

all: $(BIN)

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

install:
	install -v -m755 $(BIN) $(DESTDIR)/$(PREFIX)/bin

clean:
	$(RM) $(BIN)

.PHONY: install clean

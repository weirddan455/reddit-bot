#!/usr/bin/make -f

SHELL = /bin/sh

CC ?= cc
CFLAGS = -O3 -Wall

override target := reddit

all: $(target)
.PHONY: all

$(target): reddit.c
	$(CC) $(CFLAGS) $^ -o $@ -lcurl

clean:
	rm -v -- $(target)
.PHONY: clean

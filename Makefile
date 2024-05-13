CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lz

SRCS = gzinfo.c
OBJS = $(SRCS:.c=.o)
EXEC = gzinfo

.PHONY: all clean

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(EXEC)

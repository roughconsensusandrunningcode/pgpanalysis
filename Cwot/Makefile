#
# If you lack <sys/queue.h> and/or <sys/tree.h>, 
# uncomment the next line.
DEF = -DNOQUEUE

CFLAGS = -Wall -O2 $(DEF)

all: wot-centrality

wot-centrality: wot.c
	$(CC) $(CFLAGS) -c wot.c
	$(CC) $(LDFLAGS) -o wot-centrality wot.o -lm

clean:
	rm -f wot-centrality wot.o

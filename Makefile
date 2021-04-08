CFLAGS += -std=c99 -pthread

lr: lr.c | links.csv

links.csv:
	touch $@

run: lr
	@exec ./lr

clean:
	rm -f lr

.PHONY: clean

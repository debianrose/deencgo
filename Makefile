.PHONY: all clean test c-lib

all: c-lib deenc

c-lib:
	$(MAKE) -C leetgen

deenc: deletgen c-lib
	go build -v -o libdeenc.a

test: c-lib
	cd test && go run main.go

clean:
	$(MAKE) -C leetgen clean
	rm -f libdeenc.a
	go clean -cache

install: c-lib
	go install

.PHONY: all clean test deletgen c-lib deenc install

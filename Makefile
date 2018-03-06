all: build

run:
	export HOST_EXTRA_CFLAGS="-D_REENTRANT -lpthread -o2"
	go build -o example main/*.go
	./example
build: 
	go build -o example main/*.go
clean: 
	rm example
install: 
	go install
test: 
	go test

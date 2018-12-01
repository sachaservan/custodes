all: build

build: 
	export HOST_EXTRA_CFLAGS="-o3"
	go build -o ./bin/cutodes *.go
clean: 
	rm custodes
install: 
	go install
test: 
	go test

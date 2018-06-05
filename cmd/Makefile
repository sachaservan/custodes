all: build

build: 
	export HOST_EXTRA_CFLAGS="-o3"
	go build -o hypocert *.go
clean: 
	rm hypocert
install: 
	go install
test: 
	go test

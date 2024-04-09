all:V: generate
	go build .

fmt:V:
	go fmt .

generate:V:
	go generate .

test:V:
	go test -v .

testcov:V:
	go test -v -coverprofile=c.out .

vet:V:
	go vet .

clean:V:
	rm -f mkidatab

nuke:V: clean
	rm -f zptab.go

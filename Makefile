export GOPATH=$(PWD)/go
RDL ?= $(GOPATH)/bin/rdl

all: go/bin/globalipd go/bin/globalip-cli

go/bin/globalipd: keys go/src/globalipd go/src/GlobalIP go/src/github.com/dimfeld/httptreemux
	go install globalipd
	GOOS=linux go install globalipd

go/bin/globalip-cli: go/src/globalip-cli go/src/GlobalIP go/src/golang.org/x/crypto/ssh/terminal go/src/golang.org/x/net/proxy
	go install globalip-cli
	GOOS=linux go install globalip-cli

keys:
	rm -rf keys certs
	go run ca/gencerts.go

keys/client.p12: keys/client.key
	openssl pkcs12 -password pass:example -export -in ./certs/client.cert -inkey ./keys/client.key -out ./keys/client.p12

test-curl: keys/client.p12
	curl --cacert certs/ca.cert -E ./keys/client.p12:example https://localhost:4443/api/v1/$(USER)  -X DELETE

go/src/github.com/dimfeld/httptreemux:
	go get github.com/dimfeld/httptreemux

go/src/golang.org/x/crypto/ssh/terminal:
	go get golang.org/x/crypto/ssh/terminal

go/src/golang.org/x/net/proxy:
	go get golang.org/x/net/proxy

go/src/GlobalIP: rdl/GlobalIP.rdl $(RDL)
	mkdir -p go/src/GlobalIP
	$(RDL) -ps generate -t -o go/src/GlobalIP go-model rdl/GlobalIP.rdl
	$(RDL) -ps generate -t -o go/src/GlobalIP go-server rdl/GlobalIP.rdl
	$(RDL) -ps generate -t -o go/src/GlobalIP go-client rdl/GlobalIP.rdl

go/src/globalipd:
	mkdir -p go/src
	(cd go/src; ln -s ../globalipd)

go/src/globalip-cli:
	mkdir -p go/src
	(cd go/src; ln -s ../globalip-cli)

$(RDL):
	go get github.com/ardielle/ardielle-tools/...

bin/$(NAME): generated src/globalipd/main.go src/globalip-cli/main.go
	go install $(NAME)

src/globalipd/main.go:
	(cd $GOPATH/src; ln -s .. globalipd)

src/globalip-cli/main.go:
	(cd $GOPATH/src; ln -s .. globalip-cli)

clean::
	rm -rf go/bin go/pkg go/src keys certs go/GlobalIP

# rdl-globalip

## Making a Go server

    $ make

    $ ./go/bin/globalipd &
    YYYY/MM/DD hh:mm:ss Initialized Contacts service at 'http://localhost:4080/api/v1'

## Making a Go server with docker

    $ docker run -itd -h localhost -p 0.0.0.0:4080:4080 --name globalipd cty3000/globalipd

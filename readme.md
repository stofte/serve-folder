# Serve HTTP

WIP developer utility for serving a directory via HTTP, similar to
nodes [http-server](https://www.npmjs.com/package/http-server).
Tested on Windows only for now.

- Improve logging
- Make error handling non-fatal
- Cross-platform handling
- Default document (index.htm, index.html, etc)
- Setting/configuring mime-types?
- HTTPS (?)
- Threading/pools?

# Usage

    Basic utility for serving up a directory via HTTP
    
    Usage: servehttp.exe [OPTIONS] [WWWROOT]
    
    Arguments:
    [WWWROOT]  Server base directory. Defaults to the current directory if not set
    
    Options:
    -p, --port <PORT>                                  Server port [default: 8080]
    -b, --bind <BIND>                                  Network interface to bind [default: localhost]
    -f, --certificate-filename <CERTIFICATE_FILENAME>  Filepath for TLS certificate
    -w, --certificate-password <CERTIFICATE_PASSWORD>  Optional password for the above TLS certificate
    -h, --help                                         Print help

# Examples:

	> servehttp -p 80 C:\temp\
	Serving "C:\temp" @ localhost:80

# Certificate Notes

Creates pfx without password (or empty string password, seems unlcear?) [See more.](https://serverfault.com/a/1106205/18877).
The code below tested on WSL

    openssl pkcs12 -clcerts -nokeys -in mypfx1.pfx -out certificate.crt -password pass:foobar -passin pass:foobar
    openssl pkcs12 -cacerts -nokeys -in mypfx1.pfx -out ca-cert.ca -password pass:foobar -passin pass:foobar
    openssl pkcs12 -nocerts -nodes -in mypfx1.pfx -out private.key -password pass:foobar -passin pass:foobar -passout pass:foobaz
    openssl rsa -in private.key -out "NewKeyFile.key" -passin pass:foobaz
    cat "NewKeyFile.key" "certificate.crt" "ca-cert.ca" > PEM.pem
    openssl pkcs12 -export -certpbe NONE -keypbe NONE -nodes -nomac -CAfile ca-cert.ca -in PEM.pem -out "NewPKCSWithoutPassphraseFile.p12"

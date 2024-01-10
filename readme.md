# Serve Folder

WIP developer utility for serving a directory via HTTP(S), similar to
nodes [http-server](https://www.npmjs.com/package/http-server).

Tested on Windows only for now.

- Cross-platform handling
- Configuring mime-types?
- Threading/pools?

## Usage

    Simple CLI server utility for hosting directories over HTTP

    Usage: servefolder.exe [OPTIONS] [WWWROOT]

    Arguments:
      [WWWROOT]  Web root directory. Defaults to the current directory if not set

    Options:
      -p, --port <PORT>
              Server port [default: 8080]
      -b, --bind <BIND>
              Network interface to bind [default: 0.0.0.0]
      -f, --certificate-filename <CERTIFICATE_FILENAME>
              Filepath for TLS certificate
      -w, --certificate-password <CERTIFICATE_PASSWORD>
              Optional password for the above TLS certificate
      -t, --certificate-thumbprint <CERTIFICATE_THUMBPRINT>
              Locally installed TLS certificate thumprint to use
      -d, --default-documents <DEFAULT_DOCUMENTS>
              Default documents list. Specify option multiple times for each value in order of priority [default: index.html]
      -h, --help
              Print help

## Examples:

    C:\temp>servefolder
    14:32:44.624 [INF] Serving "C:\temp" @ http://localhost:8080

## Notes

- [OpenSSL certificate operations for "removing" password](https://serverfault.com/a/1106205/18877)
- [Reading Windows Terminal colors is not supported](https://github.com/microsoft/terminal/issues/3718)
# Schob

Schob is a client for "shovey", a mechanism for pushing jobs to client nodes. 
Currently it's specific to goiardi, but a more general implementation is 
planned.

Dependencies
------------

Running schob requires a goiardi server (both to send jobs to the schob client,
and for the schob client to send reports to) and serf running with the goiardi
server and on every client node that will run shovey jobs.

The `knife-shove` plugin from https://github.com/ctdk/knife-shove is required to
submit and administer shovey jobs.

Schob has the following golang dependencies outside of the standard library:
go-flags, toml, logger, the go-chef chef library, serf, go-uuid, and the 
chefcrypto library from goiardi (only for tests). The easiest way to install
these dependencies is to include the `-t` flag when installing schob with
`go get -t github.com/ctdk/schob`.

Installation
------------

The easiest way to install schob is with the shovey-jobs cookbook, located at
https://github.com/ctdk/shovey-jobs. At the moment it only supports Debian,
though, so for now installing on non-Debian platforms will have to install schob
by hand. If you already have a binary you can skip to number 2.

0. Set up go and configure go. (http://golang.org/doc/install.html)
1. Download schob and its dependencies.
```
	go get -t github.com/ctdk/schob
```
2. Install the schob binary.
```
	go install github.com/ctdk/schob
```
Alternately, if you downloaded a precompiled binary, put that binary somewhere
in your PATH.

Usage
-----

Contributing
------------
1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write your change
4. Write tests for your change (if applicable)
5. Run the tests, ensuring they all pass
6. Submit a Pull Request using Github

Author
------

Jeremy Bingham (<jbingham@gmail.com>)

Copyright
---------

Copyright 2014, Jeremy Bingham

License
-------

Schob is licensed under the Apache 2.0 License. See the LICENSE file for
details.

"Schob" is German for "shoved".

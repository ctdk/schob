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
these dependencies is to include the `-t` flag when using `go get` to install
schob.

Installation
------------

The easiest way to install schob is with the shovey-jobs cookbook, located at
https://github.com/ctdk/shovey-jobs. At the moment it only supports Debian,
though, so for now installing on non-Debian platforms will have to install schob
by hand. If you already have a binary you can skip to number 2.

0. Set up go and configure go. (http://golang.org/doc/install.html)
1. Download schob and its dependencies.
	> go get -t github.com/ctdk/schob
2. Install the schob binary.
	> go install github.com/ctdk/schob
   Alternately, if you downloaded a precompiled binary, put that binary 
   somewhere in your PATH.
3. Make sure goiardi is running on its server, along with serf, and that it's
   configured to use serf and shovey. You will also need to make the RSA
   public/private key pair for signing and verifying shovey jobs.
4. Start up serf on the node, making sure that it joins the same serf cluster
   goairdi's serf is running in.
5. Make sure the shovey signing public RSA key is installed on the node.
6. Create a whitelist.json file for the node, with whitelisted jobs that are
   allowed to run on the node. See the example whitelist.json file in 
   `test/whitelist.json` for guidance.
7. Run schob. Schob can take a configuration file (an example is provided in
   `test/schob-example.conf`, or it can use the following command line options:

```
  -v, --version          Print version info.
  -V, --verbose          Show verbose debug information. Repeat for more
                         verbosity.
  -c, --config=          Specify a configuration file.
  -L, --log-file=        Log to this file.
  -s, --syslog           Use syslog for logging. Incompatible with
                         -L/--log-file.
  -e, --endpoint=        Server endpoint
  -n, --node-name=       This node's name
  -k, --key-file=        Path to node client private key
  -m, --time-slew=       Time difference allowed between the node's clock and
                         the time sent in the serf command from the server.
                         Formatted like 5m, 150s, etc. Defaults to 15m.
  -w, --whitelist=       Path to JSON file containing whitelisted commands
  -t, --run-timeout=     The time, in minutes, to wait before stopping a job.
                         Separate from the timeout set from the server, this is
                         a fallback. Defaults to 45 minutes.
  -p, --sign-pub-key=    Path to public key used to verify signed requests from
                         the server.
      --serf-addr=       IP anddress and port to use for RPC communication with
                         the serf agent. Defaults to 127.0.0.1:7373.
  -q, --queue-save-file= File to save running job status to recover jobs that
                         didn't finish if schob is suddenly shut down without a
                         chance to clean up.
```

  Options specified on the command line override options in the config file. A
  typical command line invocation of schob looks like `schob -VVVV -e http://chef-server.local:4545 -n node-name.local -k /path/to/node.key -w /path/to/schob/test/whitelist.json -p /path/to/public.key --serf-addr=127.0.0.1:7373`.

Usage
-----

Once schob is running on a node, run jobs on it with the `knife-shove` plugin.
The full documentation for that can be found at 
https://github.com/ctdk/knife-shove, but here's a cheat sheet:

* To start a job:
  > knife goiardi start <command> node1, node2,...

* To start a job on all nodes in the webapp role, where 90% of the nodes must
  be up:
  > knife goiardi job start -quorum 90% 'chef-client' --search 'role:webapp'

* To see a job's status:
  > knife goiardi job status <job id>

* To get detailed information on a job on one node:
  > knife goiardi job info <job id> <node name>

* To stream a running job:
  > knife goiardi job stream <job id> <node name>

* To cancel a job:
  > knife goiardi job cancel <job id> <node name>

* To get a node's status:
  > knife goiardi node status


Contributing
------------
1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write your change
4. Write tests for your change (if applicable)
5. Run the tests, ensuring they all pass
6. Submit a Pull Request using Github

See Also
--------

* goiardi (https://github.com/ctdk/goiardi)
* knife-shove (https://github.com/ctdk/knife-shove)
* shovey-jobs cookbook (https://github.com/ctdk/shovey-jobs)
* Goiardi's shovey documentation (https://github.com/ctdk/goiardi/blob/serfing/README.md#shovey)
* Shovey API documentation (https://github.com/ctdk/goiardi/blob/serfing/shovey_api.md)

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

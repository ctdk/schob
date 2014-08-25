/*
 * Copyright (c) 2014, Jeremy Bingham (<jbingham@gmail.com>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
Schob is a client for "shovey", a mechanism for pushing jobs to client nodes. Currently it's specific to goiardi, but a more general implementation is planned.

At the moment, it's not ready for real use. It's still deep in testing. It's ready to be played with now, though. To run shovey currently you will need:

1. Checkout the "serfing" branch from goiardi
2. Create an RSA keypair for signing shovey requests
3. Install serf and run it as "serf agent"
4. Run goiardi in in-memory mode (at this writing, MySQL and Postgres in goiardi don't support shovey yet) with these extra options: `--use-serf --use-shovey --sign-priv-key=/path/to/private.key --sign-pub-key=/path/to/public.key`
5. Install knife-shove from https://github.com/ctdk/knife-shove
6. Set up the node in goiardi you want to test shovey on. I've been using the computer I do my usual goiardi dev work for most of it.
7. Install schob the usual go way
8. Note where the testing whitelist file is (probably somewhere like ~/go/src/github.com/ctdk/schob/test/whitelist.json).
9. Run schob like so: `schob -VVVV -e http://chef-server.local:4545 -n node-name.local -k /path/to/node.key -w /path/to/schob/test/whitelist.json -p /path/to/public.key --serf-addr=127.0.0.1:7373`

schob is coming together, but it's not done yet. Better docs and cookbooks for setting it up will come once it stabilizes a bit more. Tests aren't there yet either, since the goiardi and schob halves of shovey lean on each other so much. It's definitely on my mind though.
*/

package main

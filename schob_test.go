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

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/ctdk/goiardi/chefcrypto"
	"testing"
	"time"
)

var privKey *rsa.PrivateKey
var pubKey *rsa.PublicKey

func init() {
	privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	p := privKey.PublicKey
	pubKey = &p
}

func TestWhitelistFile(t *testing.T) {
	wlist, err := loadWhitelist("test/whitelist.json")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	c, ok := wlist.get("ls")
	if !ok {
		t.Errorf("expected to find 'ls', executing '%s' in whitelist, but didn't", c.(string))
	}
}

func TestCommandArgs(t *testing.T) {
	cmd := "ls /foo\\ bar"
	args := cmdArgs(cmd)
	if len(args) != 2 {
		t.Errorf("args should have had len 2, but had %d", len(args))
	}
	if args[0] != "ls" {
		t.Errorf("command should have been 'ls', got %s", args[0])
	}
	if args[1] != "/foo\\ bar" {
		t.Errorf("bad args, got %s", args[1])
	}
}

func TestCheckTimeStamp(t *testing.T) {
	timeNow := time.Now().UTC()
	timeHourAgo := time.Now().Add(time.Duration(-1) * time.Hour)
	_, err := checkTimeStamp(timeNow.Format(time.RFC3339), time.Duration(15) * time.Minute)
	if err != nil {
		t.Errorf(err.Error())
	}
	_, err = checkTimeStamp(timeHourAgo.Format(time.RFC3339), time.Duration(15) * time.Minute)
	if err == nil {
		t.Errorf("Time %s should have been bad, but it passed", timeHourAgo.String())
	}
}

func TestAssembleReqBlock(t *testing.T) {
	payload := make(map[string]string)
	payload["z"] = "a"
	payload["d"] = "d"
	payload["foo"] = "foobarbaz"
	payload["signature"] = "123456"
	expected := "d: d\nfoo: foobarbaz\nz: a"
	if assembleReqBlock(payload) != expected {
		t.Errorf("Assembled block should have been '%s', but got '%s'", expected, assembleReqBlock(payload))
	}
}

func TestVerifyRequest(t *testing.T) {
	payload := make(map[string]string)
	payload["z"] = "a"
	payload["d"] = "d"
	payload["foo"] = "foobarbaz"
	bl := assembleReqBlock(payload)
	var err error
	payload["signature"], err = chefcrypto.SignTextBlock(bl, privKey)
	if err != nil {
		t.Errorf(err.Error())
	}
	err = verifyRequest(payload["signature"], bl, pubKey)
	if err != nil {
		t.Errorf(err.Error())
	}
}

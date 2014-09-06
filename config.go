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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/ctdk/goas/v2/logger"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

const version = "0.0.1"

type conf struct {
	DebugLevel    int    `toml:"debug-level"`
	LogLevel      string `toml:"log-level"`
	LogFile       string `toml:"log-file"`
	SysLog        bool   `toml:"syslog"`
	Endpoint      string `toml:"endpoint"`
	ClientName    string `toml:"clientname"`
	KeyFileName   string `toml:"key-file"`
	Key           string
	TimeSlew      string `toml:"time-slew"`
	TimeSlewDur   time.Duration
	WhitelistFile string `toml:"whitelist"`
	RunTimeout    int    `toml:"run-timeout"`
	SigningPubKey string `toml:"sign-pub-key"`
	SerfAddr      string `toml:"serf-addr"`
	PubKey        *rsa.PublicKey
	QueueSaveFile string `toml:"queue-save-file"`
}

type options struct {
	Version       bool   `short:"v" long:"version" description:"Print version info."`
	Verbose       []bool `short:"V" long:"verbose" description:"Show verbose debug information. Repeat for more verbosity."`
	ConfFile      string `short:"c" long:"config" description:"Specify a configuration file."`
	LogFile       string `short:"L" long:"log-file" description:"Log to this file."`
	SysLog        bool   `short:"s" long:"syslog" description:"Use syslog for logging. Incompatible with -L/--log-file."`
	Endpoint      string `short:"e" long:"endpoint" description:"Server endpoint"`
	ClientName    string `short:"n" long:"node-name" description:"This node's name"`
	KeyFileName   string `short:"k" long:"key-file" description:"Path to node client private key"`
	TimeSlew      string `short:"m" long:"time-slew" description:"Time difference allowed between the node's clock and the time sent in the serf command from the server. Formatted like 5m, 150s, etc. Defaults to 15m."`
	WhitelistFile string `short:"w" long:"whitelist" description:"Path to JSON file containing whitelisted commands"`
	RunTimeout    int    `short:"t" long:"run-timeout" description:"The time, in minutes, to wait before stopping a job. Separate from the timeout set from the server, this is a fallback. Defaults to 45 minutes."`
	SigningPubKey string `short:"p" long:"sign-pub-key" description:"Path to public key used to verify signed requests from the server."`
	SerfAddr      string `long:"serf-addr" description:"IP anddress and port to use for RPC communication with the serf agent. Defaults to 127.0.0.1:7373."`
	QueueSaveFile string `short:"q" long:"queue-save-file" description:"File to save running job status to recover jobs that didn't finish if schob is suddenly shut down without a chance to clean up."`
}

var logLevelNames = map[string]int{"debug": 4, "info": 3, "warning": 2, "error": 1, "critical": 0}

func parseConfig() (*conf, error) {
	var opts = &options{}
	var config = &conf{}

	_, err := flags.Parse(opts)

	if err != nil {
		if err.(*flags.Error).Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			log.Println(err)
			os.Exit(1)
		}
	}

	if opts.ConfFile != "" {
		if _, err = toml.DecodeFile(opts.ConfFile, config); err != nil {
			return nil, err
		}
	}

	if opts.Version {
		fmt.Printf("schob version %s\n", version)
		os.Exit(0)
	}

	if opts.TimeSlew != "" {
		config.TimeSlew = opts.TimeSlew
	}
	if config.TimeSlew != "" {
		d, derr := time.ParseDuration(config.TimeSlew)
		if derr != nil {
			logger.Criticalf("Error parsing time-slew: %s", derr.Error())
			os.Exit(1)
		}
		config.TimeSlewDur = d
	} else {
		config.TimeSlewDur, _ = time.ParseDuration("15m")
	}

	if opts.LogFile != "" {
		config.LogFile = opts.LogFile
	}
	if opts.SysLog {
		config.SysLog = opts.SysLog
	}
	if config.LogFile != "" {
		if config.SysLog {
			err = fmt.Errorf("Sorry, but you can't specify both --syslog and --log-file.")
			return nil, err
		}
		lfp, err := os.Create(config.LogFile)
		if err != nil {
			return nil, err
		}
		log.SetOutput(lfp)
	}
	if dlev := len(opts.Verbose); dlev != 0 {
		config.DebugLevel = dlev
	}
	if config.LogLevel != "" {
		if lev, ok := logLevelNames[strings.ToLower(config.LogLevel)]; ok && config.DebugLevel == 0 {
			config.DebugLevel = lev
		}
	}
	if config.DebugLevel > 4 {
		config.DebugLevel = 4
	}
	config.DebugLevel = int(logger.LevelCritical) - config.DebugLevel
	logger.SetLevel(logger.LogLevel(config.DebugLevel))
	debugLevel := map[int]string{0: "debug", 1: "info", 2: "warning", 3: "error", 4: "critical"}
	log.Printf("Logging at %s level", debugLevel[config.DebugLevel])
	if config.SysLog {
		sl, err := logger.NewSysLogger("schob")
		if err != nil {
			return nil, err
		}
		logger.SetLogger(sl)
	} else {
		logger.SetLogger(logger.NewGoLogger())
	}

	if opts.SerfAddr != "" {
		config.SerfAddr = opts.SerfAddr
	}
	if config.SerfAddr == "" {
		config.SerfAddr = "127.0.0.1:7373"
	}
	if opts.Endpoint != "" {
		config.Endpoint = opts.Endpoint
	}
	if opts.ClientName != "" {
		config.ClientName = opts.ClientName
	}
	if opts.KeyFileName != "" {
		config.KeyFileName = opts.KeyFileName
	}
	if opts.WhitelistFile != "" {
		config.WhitelistFile = opts.WhitelistFile
	}
	if opts.RunTimeout != 0 {
		config.RunTimeout = opts.RunTimeout
	}
	if opts.SigningPubKey != "" {
		config.SigningPubKey = opts.SigningPubKey
	}
	if config.RunTimeout == 0 {
		config.RunTimeout = 45
	}

	if opts.QueueSaveFile != "" {
		config.QueueSaveFile = opts.QueueSaveFile
	}

	if config.KeyFileName == "" {
		err = fmt.Errorf("no private key file for node client given")
		return nil, err
	}

	fp, err := os.Open(config.KeyFileName)
	if err != nil {
		return nil, err
	}
	keyData, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil, err
	}
	config.Key = string(keyData)

	if config.SigningPubKey == "" {
		err = fmt.Errorf("No public key for signing shovey requests given")
		return nil, err
	}
	pfp, err := os.Open(config.SigningPubKey)
	if err != nil {
		return nil, err
	}
	pub, err := ioutil.ReadAll(pfp)
	if err != nil {
		return nil, err
	}
	pubBlock, _ := pem.Decode(pub)
	if pubBlock == nil {
		err = fmt.Errorf("Invalid block size for public key for shovey")
		return nil, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}
	config.PubKey = pubKey.(*rsa.PublicKey)

	return config, nil
}

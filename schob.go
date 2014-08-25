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
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ctdk/goas/v2/logger"
	"github.com/ctdk/schob/shoveyreport"
	"github.com/go-chef/chef"
	serfclient "github.com/hashicorp/serf/client"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var serfer *serfclient.RPCClient

func main() {
	config, err := parseConfig()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	clientConfig := &chef.Config{Name: config.ClientName, Key: config.Key, SkipSSL: true, BaseURL: config.Endpoint}
	chefClient, err := chef.NewClient(clientConfig)
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}

	serfer, err = serfclient.NewRPCClient(config.SerfAddr)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}
	err = serfer.UserEvent("goiardi-join", []byte(config.ClientName), true)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}

	// start the heartbeat messages
	go heartbeat(config.ClientName)

	// watch for events and queries
	streamCh := make(chan map[string]interface{}, 10)
	stream, err := serfer.Stream("*", streamCh)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}
	whitelist, err := loadWhitelist(config.WhitelistFile)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}
	log.Printf("whitelist is: %v", whitelist)

	defer serfer.Stop(stream)

	cmdKill := make(map[string]chan struct{})
	cmdRun := make(map[string]*exec.Cmd)

	for e := range streamCh {
		log.Printf("Got an event: %v", e)
		eName, _ := e["Name"]
		switch eName {
		case "shovey":
			logger.Debugf("in shovey control")
			payload := make(map[string]string)
			err = json.Unmarshal(e["Payload"].([]byte), &payload)
			if err != nil {
				logger.Errorf(err.Error())
				os.Exit(1)
			}
			logger.Debugf("Job id is: %s", payload["run_id"])
			logger.Debugf("payload is: %v", payload)
			report, err := shoveyreport.New(config.ClientName, payload["run_id"], chefClient)
			if err != nil {
				log.Println(err)
				continue
			}
			action, ok := payload["action"]
			if !ok {
				logger.Infof("No action given for command %s with job ID %s", payload["command"], payload["run_id"])
				continue
			}
			var runTimeout time.Duration
			if payload["timeout"] != "" {
				rt, err := strconv.Atoi(payload["timeout"])
				if err != nil {
					logger.Errorf("supplied timeout %s for run %s invalid: %s", payload["timeout"], payload["run_id"], err.Error())
					continue
				}
				runTimeout = time.Duration(rt)
			} else {
				runTimeout = time.Duration(config.RunTimeout)
			}

			reqBlock := assembleReqBlock(payload)
			if err = verifyRequest(payload["signature"], reqBlock, config.PubKey); err != nil {
				logger.Errorf("Command id %s running '%s' could not be verified! %s", payload["run_id"], payload["command"], err.Error())
				continue
			} else {
				logger.Debugf("job %s verified!", payload["run_id"])
			}

			switch action {
			case "start":
				c, ok := whitelist[payload["command"]]
				if !ok {
					log.Println("NACK")
					report.Status = "nacked"
					report.Error = fmt.Sprintf("command %s not in whitelist", payload["command"])
					err = report.SendReport()
					if err != nil {
						logger.Errorf("Error sending report: %s", err.Error())
					}
					continue
				}
				report.Status = "running"
				err = report.SendReport()
				if err != nil {
					logger.Errorf("Error sending good report: %s", err.Error())
				}

				logger.Debugf("Will execute %s", c)
				args := cmdArgs(c.(string))
				cmd := exec.Command(args[0], args[1:]...)
				var out bytes.Buffer
				var stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				cerr := cmd.Start()
				if cerr != nil {
					report.Error = cerr.Error()
					report.Status = "invalid"
					report.SendReport()
					continue
				}
				cmdKill[payload["run_id"]] = make(chan struct{}, 1)
				cmdRun[payload["run_id"]] = cmd

				go func() {
					cerrCh := make(chan error, 1)
					go func() {
						cerrCh <- cmd.Wait()
					}()
					select {
					case cerr := <-cerrCh:
						close(cerrCh)
						close(cmdKill[payload["run_id"]])
						delete(cmdKill, payload["run_id"])
						if cerr != nil {
							report.Error = cmd.ProcessState.String()
							report.ErrMsg = stderr.String()
							sysInfo := cmd.ProcessState.Sys().(syscall.WaitStatus)
							report.ExitStatus = uint8(sysInfo.ExitStatus())
							report.Status = "failed"
						} else {
							report.Output = out.String()
							report.ErrMsg = stderr.String()
							report.Status = "completed"
						}
						report.SendReport()
						// get rid of the command now?
						delete(cmdRun, payload["run_id"])
						logger.Infof("Finished job %s", payload["run_id"])
						return
					case <-cmdKill[payload["run_id"]]:
						// Probably want to tell the
						// server what happened here
						// later
						log.Printf("cancelling job %s", payload["run_id"])
						cmd, ok := cmdRun[payload["run_id"]]
						if !ok {
							log.Printf("Job ID %s not found or finished running", payload["run_id"])
							return
						}

						errCh := make(chan error, 1)

						go func() {
							errCh <- cmd.Process.Signal(os.Interrupt)
						}()

						select {
						case err := <-errCh:
							if err != nil {
								logger.Errorf(err.Error())
							} else {
								logger.Debugf("cancelling was successful")
								delete(cmdRun, payload["run_id"])
							}
							close(cerrCh)
							close(cmdKill[payload["run_id"]])
							delete(cmdKill, payload["run_id"])
						case <-time.After(time.Duration(120) * time.Second):
							err := cmd.Process.Kill()
							if err != nil {
								logger.Errorf(err.Error())
							} else {
								close(cerrCh)
								close(cmdKill[payload["run_id"]])
								delete(cmdKill, payload["run_id"])
								logger.Debugf("Job %s timed out", payload["run_id"])

							}
						}
					// should also be configurable: a
					// really-really timeout separate from
					// the main one the server uses, in case
					// something gets out of hand.
					case <-time.After(runTimeout * time.Minute):
						logger.Infof("Job %s running too long, killing", payload["run_id"])
						cmd, ok := cmdRun[payload["run_id"]]
						if !ok {
							logger.Debugf("Job ID %s not found or finished running", payload["run_id"])
							return
						}
						err := cmd.Process.Kill()
						if err != nil {
							logger.Errorf(err.Error())
						}
					}
				}()
			case "cancel":
				if p, ok := cmdKill[payload["run_id"]]; ok {
					logger.Debugf("Sending noticd to kill job %s", payload["run_id"])
					p <- struct{}{}
					continue
				}
				logger.Debugf("Cancelling job %s failed, because the job was no longer running")
			default:
				logger.Warningf("Unknown action %s", action)
				continue
			}
		default:
			logger.Debugf("Didn't know what to do with %s", eName.(string))
		}
	}
}

func heartbeat(clientName string) {
	logger.Debugf("In heartbeat")
	ticker := time.NewTicker(time.Second * time.Duration(30))
	payload := map[string]string{"node": clientName, "status": "up"}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	for _ = range ticker.C {
		respCh := make(chan serfclient.NodeResponse, 1)
		q := &serfclient.QueryParam{Name: "node_status", Payload: jsonPayload, RespCh: respCh}
		err = serfer.Query(q)
		go func() {
			r := <-respCh
			logger.Debugf("got response from server for heartbeat: %s", string(r.Payload))
		}()
		logger.Debugf("should have sent a node status query in the ticker loop")
		if err != nil {
			logger.Errorf("Error sending heartbeat message: %s", err.Error())
		}
	}
}

func loadWhitelist(wlFile string) (map[string]interface{}, error) {
	fp, err := os.Open(wlFile)
	defer fp.Close()
	if err != nil {
		return nil, err
	}
	wl := make(map[string]interface{})
	dec := json.NewDecoder(fp)
	if err = dec.Decode(&wl); err != nil {
		return nil, err
	}
	wls := wl["whitelist"].(map[string]interface{})
	return wls, nil
}

func cmdArgs(cmd string) []string {
	re := regexp.MustCompile(`\\$`)
	argsRaw := strings.Split(cmd, " ")
	var args []string
	for i := 0; i < len(argsRaw); i++ {
		u := argsRaw[i]
		for re.MatchString(u) {
			i++
			if i >= len(argsRaw) {
				break
			}
			u = u + " " + argsRaw[i]
		}
		args = append(args, u)
	}
	return args
}

func assembleReqBlock(payload map[string]string) string {
	var pkeys []string
	for k := range payload {
		if k == "signature" {
			continue
		}
		pkeys = append(pkeys, k)
	}
	sort.Strings(pkeys)
	parr := make([]string, len(pkeys))
	for i, k := range pkeys {
		parr[i] = payload[k]
	}
	payloadBlock := strings.Join(parr, "\n")
	return payloadBlock
}

func verifyRequest(signature, reqBlock string, pubKey *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	sigSha := sha1.Sum([]byte(reqBlock))
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, sigSha[:], sig)
}

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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/ctdk/goas/v2/logger"
	"github.com/ctdk/schob/shoveyreport"
	"github.com/go-chef/chef"
	serfclient "github.com/hashicorp/serf/client"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var serfer *serfclient.RPCClient

type queueManage struct {
	shuttingDown bool
	jobsRunning  map[string]bool
	saveFile     string
	sync.RWMutex
}

type wl struct {
	items map[string]interface{}
	sync.RWMutex
}

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

	// set up signal handlers
	qm := new(queueManage)
	err = qm.checkOldJobs(config.QueueSaveFile, config, chefClient)
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)
	}

	whitelist, err := loadWhitelist(config.WhitelistFile)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}
	logger.Infof("whitelist is: %v", whitelist)

	handleSignals(qm, config, chefClient, serfer, whitelist)

	// start the heartbeat messages
	go heartbeat(config.ClientName)

	// watch for events and queries
	streamCh := make(chan map[string]interface{}, 10)
	stream, err := serfer.Stream("*", streamCh)
	if err != nil {
		logger.Criticalf(err.Error())
		os.Exit(1)
	}

	defer serfer.Stop(stream)

	cmdKill := make(map[string]chan struct{})
	cmdRun := make(map[string]*exec.Cmd)

	for e := range streamCh {
		go func() {
			logger.Debugf("Got an event: %v", e)
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
					logger.Errorf(err.Error())
					return
				}
				action, ok := payload["action"]
				if !ok {
					logger.Infof("No action given for command %s with job ID %s", payload["command"], payload["run_id"])
					report.Error = fmt.Sprintf("No action given for command %s with job ID %s", payload["command"], payload["run_id"])
					report.Status = "invalid"
					report.SendReport()
					return
				}
				var runTimeout time.Duration
				if payload["timeout"] != "" {
					rt, err := strconv.Atoi(payload["timeout"])
					if err != nil {
						logger.Errorf("supplied timeout %s for run %s invalid: %s", payload["timeout"], payload["run_id"], err.Error())
						report.Error = err.Error()
						report.Status = "invalid"
						report.SendReport()
						return
					}
					runTimeout = time.Duration(rt)
				} else {
					runTimeout = time.Duration(config.RunTimeout) * time.Second
				}
				logger.Debugf("timeout is %d", runTimeout)

				reqBlock := assembleReqBlock(payload)
				if err = verifyRequest(payload["signature"], reqBlock, config.PubKey); err != nil {
					logger.Errorf("Command id %s running '%s' could not be verified! %s", payload["run_id"], payload["command"], err.Error())
					report.Error = fmt.Sprintf("Command id %s running '%s' could not be verified! %s", payload["run_id"], payload["command"], err.Error())
					report.Status = "invalid"
					report.SendReport()
					return
				}
				logger.Debugf("job %s verified!", payload["run_id"])
				tok, err := checkTimeStamp(payload["time"], config.TimeSlewDur)
				if !tok {
					logger.Errorf(err.Error())
					report.Error = err.Error()
					report.Status = "invalid"
					report.SendReport()
					return
				}

				switch action {
				case "start":
					if err = qm.addJob(payload["run_id"]); err != nil {
						logger.Errorf(err.Error())
						report.Status = "shutdown"
						report.Error = "shovey client was shutting down"
						err = report.SendReport()
						if err != nil {
							logger.Errorf("Error sending report: %s", err.Error())
						}
						return
					}
					c, ok := whitelist.get(payload["command"])
					if !ok {
						logger.Infof("NACK")
						report.Status = "nacked"
						report.Error = fmt.Sprintf("command %s not in whitelist", payload["command"])
						qm.removeJob(payload["run_id"])
						err = report.SendReport()
						if err != nil {
							logger.Errorf("Error sending report: %s", err.Error())
						}
						return
					}
					report.Status = "running"
					err = report.SendReport()
					if err != nil {
						logger.Errorf("Error sending good report: %s", err.Error())
					}

					logger.Debugf("Will execute %s", c)
					args := cmdArgs(c.(string))
					cmd := exec.Command(args[0], args[1:]...)
					out := new(bytes.Buffer)
					stderr := new(bytes.Buffer)
					cmd.Stdout = out
					cmd.Stderr = stderr
					cerr := cmd.Start()
					if cerr != nil {
						report.Error = cerr.Error()
						report.Status = "invalid"
						report.SendReport()
						return
					}
					cmdKill[payload["run_id"]] = make(chan struct{}, 1)
					cmdRun[payload["run_id"]] = cmd

					outch := make(chan struct{}, 1)
					errch := make(chan struct{}, 1)
					waitch := make(chan struct{}, 2)

					stdoutReport, err := shoveyreport.NewOutputReport(config.ClientName, payload["run_id"], "stdout", chefClient)
					if err != nil {
						report.Error = err.Error()
						report.Status = "bad_fh"
						report.SendReport()
						return
					}
					stderrReport, err := shoveyreport.NewOutputReport(config.ClientName, payload["run_id"], "stderr", chefClient)
					if err != nil {
						report.Error = err.Error()
						report.Status = "bad_fh"
						report.SendReport()
						return
					}

					go readOut(out, stdoutReport, runTimeout, waitch, outch)
					go readOut(stderr, stderrReport, runTimeout, waitch, errch)

					cerrCh := make(chan error, 1)
					go func() {
						cerrCh <- cmd.Wait()
					}()
					select {
					case cerr := <-cerrCh:
						logger.Debugf("got cerr/wait")
						close(cerrCh)
						close(cmdKill[payload["run_id"]])
						delete(cmdKill, payload["run_id"])
						if cerr != nil {
							report.Error = cmd.ProcessState.String()
							//report.Stderr = stderr.String()
							sysInfo := cmd.ProcessState.Sys().(syscall.WaitStatus)
							report.ExitStatus = uint8(sysInfo.ExitStatus())
							report.Status = "failed"
						} else {
							//report.Output = out.String()
							//report.Stderr = stderr.String()
							report.Status = "completed"
						}
						report.SendReport()
						// get rid of the command now?
						delete(cmdRun, payload["run_id"])
						logger.Infof("Finished job %s", payload["run_id"])
						qm.removeJob(payload["run_id"])
						logger.Infof("removed job from queue manager")
					case <-cmdKill[payload["run_id"]]:
						// Probably want to tell the
						// server what happened here
						// later
						logger.Infof("cancelling job %s", payload["run_id"])
						cmd, ok := cmdRun[payload["run_id"]]
						if !ok {
							logger.Errorf("Job ID %s not found or finished running", payload["run_id"])
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
								qm.removeJob(payload["run_id"])
							}
							close(cmdKill[payload["run_id"]])
							delete(cmdKill, payload["run_id"])
						case <-time.After(time.Duration(120) * time.Second):
							err := cmd.Process.Kill()
							if err != nil {
								logger.Errorf(err.Error())
							} else {
								close(cmdKill[payload["run_id"]])
								delete(cmdKill, payload["run_id"])
								qm.removeJob(payload["run_id"])
								logger.Debugf("Job %s timed out", payload["run_id"])

							}
						}
					// should also be configurable: a
					// really-really timeout separate from
					// the main one the server uses, in case
					// something gets out of hand.
					case <-time.After(runTimeout * time.Second):
						logger.Infof("Job %s running too long, killing", payload["run_id"])
						cmd, ok := cmdRun[payload["run_id"]]
						if !ok {
							logger.Debugf("Job ID %s not found or finished running", payload["run_id"])
							return
						}
						err := cmd.Process.Kill()
						if err != nil {
							logger.Errorf(err.Error())
						} else {
							qm.removeJob(payload["run_id"])
						}
						report.Status = "failed"
						report.Error = fmt.Sprintf("Job %s on node %s timed out", report.RunID, report.Node)
						report.SendReport()
					}
					logger.Debugf("time to send the wait")
					waitch <- struct{}{}
					waitch <- struct{}{}
					<-outch
					<-errch
				case "cancel":
					if p, ok := cmdKill[payload["run_id"]]; ok {
						logger.Debugf("Sending notice to kill job %s", payload["run_id"])
						p <- struct{}{}
						return
					}
					logger.Debugf("Cancelling job %s failed, because the job was no longer running")
				default:
					logger.Warningf("Unknown action %s", action)
					return
				}
			default:
				if _, ok := eName.(string); ok {
					logger.Debugf("Didn't know what to do with %s", eName.(string))
				} else {
					logger.Debugf("Got an event we didn't know what to do with")
				}
			}
		}()
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

func loadWhitelist(wlFile string) (*wl, error) {
	fp, err := os.Open(wlFile)
	defer fp.Close()
	if err != nil {
		return nil, err
	}
	wlist := make(map[string]interface{})
	dec := json.NewDecoder(fp)
	if err = dec.Decode(&wlist); err != nil {
		return nil, err
	}
	wls := &wl{}
	wls.items = wlist["whitelist"].(map[string]interface{})
	return wls, nil
}

func (w *wl) get(key string) (interface{}, bool) {
	w.RLock()
	defer w.RUnlock()
	c, ok := w.items[key]
	return c, ok
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
		parr[i] = fmt.Sprintf("%s: %s", k, payload[k])
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

func handleSignals(qm *queueManage, config *conf, chefClient *chef.Client, serfer *serfclient.RPCClient, whitelist *wl) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func(qm *queueManage, config *conf, chefClient *chef.Client, serfer *serfclient.RPCClient, whitelist *wl) {
		for sig := range c {
			logger.Debugf("Received signal %s", sig)
			switch sig {
			case os.Interrupt, syscall.SIGTERM:
				logger.Infof("Shutting down")
				qm.setShutDown()
				sd := make(chan struct{}, 1)
				go func() {
					select {
					case <-sd:
						os.Exit(0)
					case <-time.After(time.Duration(120) * time.Second):
						logger.Errorf("Not all jobs ended before exiting")
						os.Exit(1)
					}
				}()
				for {
					if qm.numberOfJobs() != 0 {
						logger.Infof("Waiting for %d jobs to finish before shutting down...", qm.numberOfJobs())
						time.Sleep(time.Duration(5) * time.Second)
					} else {
						logger.Infof("No jobs remaining")
						sd <- struct{}{}
						break
					}
				}
			case syscall.SIGHUP:
				var err error
				logger.Infof("Reloading configuration...")
				config, err = parseConfig()
				if err != nil {
					logger.Criticalf(err.Error())
					os.Exit(1)
				}
				clientConfig := &chef.Config{Name: config.ClientName, Key: config.Key, SkipSSL: true, BaseURL: config.Endpoint}
				chefClient, err = chef.NewClient(clientConfig)
				if err != nil {
					logger.Criticalf(err.Error())
					os.Exit(1)
				}

				serfer, err = serfclient.NewRPCClient(config.SerfAddr)
				if err != nil {
					logger.Criticalf(err.Error())
					os.Exit(1)
				}
				whitelist.Lock()
				wl, err := loadWhitelist(config.WhitelistFile)
				if err != nil {
					logger.Criticalf(err.Error())
					os.Exit(1)
				}
				whitelist.items = wl.items
				whitelist.Unlock()
			default:
				logger.Infof("Got signal %s %v, not handled", sig, sig)
			}
		}
	}(qm, config, chefClient, serfer, whitelist)
}

func (q *queueManage) setShutDown() {
	q.Lock()
	defer q.Unlock()
	q.shuttingDown = true
}

func (q *queueManage) addJob(jobID string) error {
	q.Lock()
	q.Unlock()
	if q.shuttingDown {
		return fmt.Errorf("shutting down, not accepting new jobs")
	}
	if q.jobsRunning == nil {
		q.jobsRunning = make(map[string]bool)
	}
	q.jobsRunning[jobID] = true
	return q.saveStatus()

}

func (q *queueManage) removeJob(jobID string) error {
	q.Lock()
	defer q.Unlock()
	delete(q.jobsRunning, jobID)
	return q.saveStatus()
}

func (q *queueManage) numberOfJobs() int {
	q.RLock()
	defer q.RUnlock()
	i := len(q.jobsRunning)
	return i
}

func (q *queueManage) saveStatus() error {
	if q.saveFile == "" {
		return nil
	}
	fp, err := ioutil.TempFile(path.Dir(q.saveFile), "qstat")
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(fp)
	err = enc.Encode(q.jobsRunning)
	if err != nil {
		fp.Close()
		return err
	}
	err = fp.Close()
	if err != nil {
		return err
	}
	return os.Rename(fp.Name(), q.saveFile)
}

func (q *queueManage) checkOldJobs(saveFile string, config *conf, chefClient *chef.Client) error {
	if saveFile == "" {
		// we decided not to keep track of possibly orphaned jobs
		return nil
	}
	q.Lock()
	q.saveFile = saveFile
	q.Unlock()
	fp, err := os.Open(q.saveFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dec := gob.NewDecoder(fp)
	mj := make(map[string]bool)
	err = dec.Decode(&mj)
	if err != nil {
		fp.Close()
		return err
	}
	err = fp.Close()
	if err != nil {
		return err
	}

	if len(mj) != 0 {
		logger.Debugf("Found what appear to be %d jobs that weren't able to finish the last time schob was running", len(mj))
		for k := range mj {
			report, err := shoveyreport.New(config.ClientName, k, chefClient)
			if err != nil {
				return err
			}
			report.Status = "killed"
			report.Error = fmt.Sprintf("job %s on node %s seems to have been killed abruptly by schob not having a chance to shut down in an orderly fashion", k, config.ClientName)
			report.SendReport()
		}
	} else {
		logger.Debugf("No leftover jobs from before")
	}
	return nil
}

func readOut(reader *bytes.Buffer, outputReporter *shoveyreport.OutputReport, runTimeout time.Duration, stopch, finishch chan struct{}) {
	bufch := make(chan struct{}, 1)
	holdch := make(chan struct{}, 1)
	holdch <- struct{}{}
	readstop := false
	// make runTimeout a little longer than the execution timeout
	t := float64(runTimeout) * 1.1
	timeout := time.Duration(t)
	go func() {
		logger.Debugf("In read go func")
		for readstop == false {
			<-holdch
			if reader.Len() >= 1024 {
				bufch <- struct{}{}
			} else {
				holdch <- struct{}{}
			}
			time.Sleep(time.Duration(100) * time.Microsecond)
		}
		logger.Debugf("leaving read go func")
	}()
Loop:
	for {
		select {
		case <-bufch:
			logger.Debugf("reading %s at seq %d", outputReporter.OutputType, outputReporter.Seq)
			p := make([]byte, 1024)
			b, e := reader.Read(p)
			poutput := string(p)
			holdch <- struct{}{}
			logger.Debugf("Read %d bytes", b)
			if e != nil && e != io.EOF {
				logger.Errorf(e.Error())
			}
			err := outputReporter.SendReport(poutput, false)
			if err != nil {
				logger.Errorf(err.Error())
			}
		case <-stopch:
			<-holdch
			logger.Debugf("%s reading after the end of execution, seq %d", outputReporter.OutputType, outputReporter.Seq)
			logger.Debugf("reader is %d bytes", reader.Len())
			output := reader.String()
			holdch <- struct{}{}
			err := outputReporter.SendReport(output, true)
			if err != nil {
				logger.Errorf(err.Error())
			}
			break Loop
		case <-time.After(timeout * time.Second):
			<-holdch
			logger.Infof("Reached timeout reading %s for %s on node %s, at seq %d", outputReporter.RunID, outputReporter.Node, outputReporter.Seq)
			err := outputReporter.SendReport(reader.String(), true)
			holdch <- struct{}{}
			if err != nil {
				logger.Errorf(err.Error())
			}
			break Loop
		}
	}
	readstop = true
	finishch <- struct{}{}
}

func checkTimeStamp(timestamp string, slew time.Duration) (bool, error) {
	timeNow := time.Now().UTC()
	timeHeader, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false, err
	}
	tdiff := timeNow.Sub(timeHeader)
	if tdiff < 0 {
		tdiff = -tdiff
	}
	if tdiff > slew {
		err = fmt.Errorf("Authentication failed. Please check your system's clock.")
		return false, err
	}
	return true, nil
}

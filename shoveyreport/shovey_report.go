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

// Package shoveyreport creates a report on the status of a shovey run to send
// to the calling server.
package shoveyreport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/codeskyblue/go-uuid"
	"github.com/go-chef/chef"
	"net/http"
	"sync"
	"time"
)

// Report is the struct that holds all the information to send.
type Report struct {
	Node          string `json:"node_name"`
	RunID         string `json:"run_id"`
	Status        string `json:"status"`
	Stderr        string `json:"stderr"`
	ExitStatus    uint8  `json:"exit_status"`
	Error         string `json:"error"`
	Output        string `json:"output"`
	RunDuration   int    `json:"duration"`
	ProtocolMajor int    `json:"protocol_major"`
	ProtocolMinor int    `json:"protocol_minor"`
	chefClient    *chef.Client
}

type OutputReport struct {
	Node string `json:"node_name"`
	RunID string `json:"run_id"`
	Seq int `json:"seq"`
	IsLast bool `json:"is_last"`
	OutputType string `json:"output_type"`
	Output string `json:"output"`
	ProtocolMajor int    `json:"protocol_major"`
	ProtocolMinor int    `json:"protocol_minor"`
	chefClient *chef.Client
	sync.Mutex
}

const shoveyProtoMajorVersion = 0
const shoveyProtoMinorVersion = 1

// New creates a new report.
func New(node, runID string, chefClient *chef.Client) (*Report, error) {
	if runID == "" {
		err := fmt.Errorf("No runID provided")
		return nil, err
	}
	if node == "" {
		err := fmt.Errorf("No node name provided")
		return nil, err
	}
	if u := uuid.Parse(runID); u == nil {
		err := fmt.Errorf("runID %s did not validate as a UUID", runID)
		return nil, err
	}
	r := &Report{Node: node, RunID: runID, ProtocolMajor: shoveyProtoMajorVersion, ProtocolMinor: shoveyProtoMinorVersion, chefClient: chefClient}
	return r, nil
}

// SendReport sends a report on this shovey run back to the goiardi server.
func (r *Report) SendReport() error {
	jsonReport, err := json.Marshal(r)
	if err != nil {
		return err
	}
	rbody := bytes.NewReader(jsonReport)
	req, err := r.chefClient.NewRequest("PUT", r.shoveyURL(), rbody)
	if err != nil {
		return err
	}
	respMap := make(map[string]interface{})
	resp, err := r.chefClient.Do(req, &respMap)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Request status was %d: returned %s, and %v in the response", resp.StatusCode, resp.Status, respMap)
		return err
	}
	return nil
}

func (r *Report) shoveyURL() string {
	url := fmt.Sprintf("shovey/jobs/%s/%s", r.RunID, r.Node)
	return url
}

// NewOutputReport builds a new reporter for streaming output (stdout and 
// stderr) from a job back to the server.
func NewOutputReport(node, runID, outputType string, chefClient *chef.Client) (*OutputReport, error) {
	if runID == "" {
		err := fmt.Errorf("No runID provided")
		return nil, err
	}
	if node == "" {
		err := fmt.Errorf("No node name provided")
		return nil, err
	}
	if outputType == "" {
		err := fmt.Errorf("No output type provided")
		return nil, err
	}
	if u := uuid.Parse(runID); u == nil {
		err := fmt.Errorf("runID %s did not validate as a UUID", runID)
		return nil, err
	}
	r := &OutputReport{ Node: node, RunID: runID, OutputType: outputType, ProtocolMajor: shoveyProtoMajorVersion, ProtocolMinor: shoveyProtoMinorVersion, Seq: 0, chefClient: chefClient }
	return r, nil
}

// SendReport sends updated stream output from a job back to the server.
func (sr *OutputReport) SendReport(output string, isLast bool) error {
	sr.Lock()
	defer sr.Unlock()
	sr.Output = output
	sr.IsLast = isLast

	logger.Debugf("Output to send for %s:\n######\n\n%s\n\n#######", sr.OutputType, sr.Output)

	jsonReport, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	sr.Seq++

	rbody := bytes.NewReader(jsonReport)
	req, err := sr.chefClient.NewRequest("PUT", sr.streamURL(), rbody)
	if err != nil {
		return err
	}
	respMap := make(map[string]interface{})
	resp, err := sr.chefClient.Do(req, &respMap)
	if err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		if resp.StatusCode != http.StatusOK {
			resp, err = sr.chefClient.Do(req, &respMap)
			if err != nil {
				return err
			}
		} else {
			break
		}
		time.Sleep(time.Duration(10) * time.Second)
	}
	// if that still didn't work...
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("Couldn't send stream PUT after 30 tries. Last request status was %d: returned %s, and %v in the response", resp.StatusCode, resp.Status, respMap)
		return err
	}
	return nil
}

func (sr *OutputReport) streamURL() string {
	url := fmt.Sprintf("shovey/stream/%s/%s", sr.RunID, sr.Node)
	return url
}

// Copyright 2022 Nick Rosbrook
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package strongswan provides an i3 barista module for
// strongSwan VPNs.
package strongswan

import (
	"context"
	"errors"
	"net/url"
	"time"

	"barista.run/bar"
	"barista.run/base/value"
	"barista.run/outputs"

	"github.com/strongswan/govici/vici"
)

// Info contains information about the strongSwan VPN.
type Info struct {
	// Error is set if an error was encountered when retrieving the
	// information.
	Error error

	IKE       string
	Child     string
	VirtualIP string

	upIKE   bool
	upChild bool

	valid bool
}

// Connected returns true if the IKE and Child SAs are UP.
func (i *Info) Connected() bool {
	return i.upIKE && i.upChild
}

// Connecting returns true if one, but not both of, the IKE and Child SAs are
// up.
func (i *Info) Connecting() bool {
	return i.upIKE != i.upChild
}

// Enabled returns true if the module is enabled, i.e. it is able to
// communicate with a charon daemon.
func (i *Info) Enabled() bool {
	return i.valid
}

// Module implements bar.Module.
type Module struct {
	outputFunc value.Value

	viciSockNet  string
	viciSockAddr string
	session      *vici.Session
	events       chan vici.Event
}

// New returns a new default strongswan Module.
func New() *Module {
	m := &Module{}
	m.Output(func(i Info) bar.Output {
		if i.Connected() {
			return outputs.Text(i.IKE)
		}
		return nil
	})
	return m
}

// NewWithSocket returns a new strongswan Module with
// with a specified vici socket.
func NewWithSocket(socket string) *Module {
	m := New()

	u, err := url.Parse(socket)
	if err != nil {
		panic(err)
	}

	m.viciSockNet = u.Scheme
	m.viciSockAddr = u.Host

	return m
}

// Output configures a module to display the output of a user-defined function.
func (m *Module) Output(outputFunc func(Info) bar.Output) *Module {
	m.outputFunc.Set(outputFunc)
	return m
}

// Stream implements the bar.Module Stream method.
func (m *Module) Stream(sink bar.Sink) {
	outputFunc := m.outputFunc.Get().(func(Info) bar.Output)
	nextOutputFunc, done := m.outputFunc.Subscribe()
	defer done()

	var (
		info Info
		opt  vici.SessionOption
	)

	if m.viciSockNet != "" && m.viciSockAddr != "" {
		opt = vici.WithAddr(m.viciSockNet, m.viciSockAddr)
	}

	// This loop runs until we have an active vici.Session. If
	// charon is not running, we will not be able to establish
	// as session, so run this loop until that happens.
	m.session, info.Error = vici.NewSession(opt)
	for m.session == nil {
		sink.Output(outputFunc(info))

		select {
		case <-nextOutputFunc:
			outputFunc = m.outputFunc.Get().(func(Info) bar.Output)

		case <-time.After(10 * time.Second):
			m.session, info.Error = vici.NewSession(opt)
		}
	}
	info.valid = true

	err := m.subscribe()
	if err != nil {
		info.Error = err
		sink.Output(outputFunc(info))
		return
	}
	defer m.Close()

	info = m.currentInfo()
	for {
		sink.Output(outputFunc(info))

		select {
		case <-nextOutputFunc:
			outputFunc = m.outputFunc.Get().(func(Info) bar.Output)

		case ev := <-m.events:
			info = formatInfoFromEvent(ev)
		}
	}
}

func (m *Module) Close() error {
	if m.session == nil {
		return nil
	}

	err := m.session.UnsubscribeAll()
	if err != nil {
		return err
	}

	err = m.session.Close()
	if err != nil {
		return err
	}

	return nil
}

type ikeSA struct {
	Name string `vici:"-"`

	State           string             `vici:"state"`
	LocalVirtualIPs []string           `vici:"local-vips"`
	ChildSAs        map[string]childSA `vici:"child-sas"`
}

type childSA struct {
	Name  string `vici:"name"`
	State string `vici:"state"`
}

func (m *Module) listsas() ([]ikeSA, error) {
	ms, err := m.session.StreamedCommandRequest("list-sas", "list-sa", nil)
	if err != nil {
		return nil, err
	}

	sas := make([]ikeSA, 0)
	for _, m := range ms.Messages() {
		if len(m.Keys()) == 0 {
			continue
		}

		if err := m.Err(); err != nil {
			return nil, err
		}

		sa := ikeSA{Name: m.Keys()[0]}
		tmp, ok := m.Get(sa.Name).(*vici.Message)
		if !ok {
			return nil, errors.New("unexpected message format")
		}

		err = vici.UnmarshalMessage(tmp, &sa)
		if err != nil {
			return nil, err
		}

		sas = append(sas, sa)
	}

	return sas, nil
}

func (m *Module) subscribe() error {
	err := m.session.Subscribe("ike-updown", "child-updown")
	if err != nil {
		return err
	}

	m.events = make(chan vici.Event, 16)

	go func() {
		for {
			ev, err := m.session.NextEvent(context.Background())
			if err != nil {
				return
			}

			switch ev.Name {
			case "ike-updown", "child-updown":
				m.events <- ev
			}
		}
	}()

	return nil
}

func formatInfoFromSAs(sas []ikeSA) Info {
	info := Info{valid: true}

	// Just choose the first IKE SA. We can add more complex
	// logic later if necessary.
	if len(sas) == 0 {
		return info
	}
	sa := sas[0]

	info.IKE = sa.Name
	info.upIKE = sa.State == "ESTABLISHED"

	// Again, be lazy for now.
	if len(sa.LocalVirtualIPs) > 0 {
		info.VirtualIP = sa.LocalVirtualIPs[0]
	}

	if sa.ChildSAs == nil {
		return info
	}

	// Yet more laziness. These are good enough for the common cases
	// though.
	var child childSA
	for _, child = range sa.ChildSAs {
		break
	}

	info.Child = child.Name
	info.upChild = child.State == "INSTALLED"

	return info
}

func (m *Module) currentInfo() Info {
	info := Info{valid: true}

	sas, err := m.listsas()
	if err != nil {
		info.Error = err
		return info
	}

	return formatInfoFromSAs(sas)
}

func formatInfoFromEvent(ev vici.Event) Info {
	info := Info{valid: true}
	m := ev.Message

	if len(m.Keys()) == 0 {
		info.Error = errors.New("unexpected message format")
		return info
	}

	var sa ikeSA

	// The only possible keys for these event types are "up", and
	// "<IKE SA name>".  It is a wonky format, but we can get the IKE SA
	// name by checking whatever is NOT "up."
	for _, key := range m.Keys() {
		if key != "up" {
			sa.Name = key
			break
		}
	}

	tmp, ok := m.Get(sa.Name).(*vici.Message)
	if !ok {
		info.Error = errors.New("unexpected message format")
		return info
	}

	err := vici.UnmarshalMessage(tmp, &sa)
	if err != nil {
		info.Error = err
		return info
	}

	return formatInfoFromSAs([]ikeSA{sa})
}

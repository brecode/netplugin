package vpp

import (
	"github.com/ligato/cn-infra/core"
	"github.com/ligato/cn-infra/datasync/resync"
	"github.com/ligato/vpp-agent/plugins/govppmux"

	"github.com/ligato/cn-infra/db/keyval/etcdv3"
	"github.com/ligato/cn-infra/httpmux"
	"github.com/ligato/cn-infra/logging/logrus"
	"github.com/ligato/cn-infra/messaging/kafka"
	"github.com/ligato/cn-infra/servicelabel"

	"github.com/ligato/cn-infra/logging/logmanager"
	"github.com/ligato/cn-infra/statuscheck"
	"github.com/ligato/vpp-agent/plugins/defaultplugins"
	"github.com/ligato/vpp-agent/plugins/linuxplugin"
)

// Flavour glues together multiple plugins to translate ETCD configuration into VPP.
type Flavour struct {
	injected     bool
	Logrus       logrus.Plugin
	HTTP         httpmux.Plugin
	LogManager   logmanager.Plugin
	ServiceLabel servicelabel.Plugin
	StatusCheck  statuscheck.Plugin
	Etcd         etcdv3.Plugin
	Kafka        kafka.Plugin
	Resync       resync.Plugin
	GoVPP        govppmux.GOVPPPlugin
	Linux        linuxplugin.Plugin
	VPP          defaultplugins.Plugin
}

// Inject sets object references
func (f *Flavour) Inject() error {
	if f.injected {
		return nil
	}
	f.injected = true
	f.HTTP.LogFactory = &f.Logrus
	f.LogManager.ManagedLoggers = &f.Logrus
	f.LogManager.HTTP = &f.HTTP
	f.StatusCheck.HTTP = &f.HTTP
	f.Etcd.LogFactory = &f.Logrus
	f.Etcd.ServiceLabel = &f.ServiceLabel
	f.Etcd.StatusCheck = &f.StatusCheck
	f.Kafka.LogFactory = &f.Logrus
	f.Kafka.ServiceLabel = &f.ServiceLabel
	f.Kafka.StatusCheck = &f.StatusCheck
	f.GoVPP.StatusCheck = &f.StatusCheck
	f.GoVPP.LogFactory = &f.Logrus
	f.VPP.ServiceLabel = &f.ServiceLabel
	f.VPP.Kafka = &f.Kafka
	f.VPP.GoVppmux = &f.GoVPP
	f.VPP.Linux = &f.Linux

	return nil
}

// Plugins combines Generic Plugins and Standard VPP Plugins + (their ETCD Connector/Adapter with RESYNC)
func (f *Flavour) Plugins() []*core.NamedPlugin {
	f.Inject()
	return core.ListPluginsInFlavor(f)
}

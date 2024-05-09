package ipgeo

import "github.com/BYT0723/NTrace-core/util"

type tokenData struct {
	ipinsight string
	ipinfo    string
	ipleo     string
}

var token = tokenData{
	ipinsight: util.GetenvDefault("NEXTTRACE_IPINSIGHT_TOKEN", ""),
	ipinfo:    util.GetenvDefault("NEXTTRACE_IPINFO_TOKEN", ""),
	ipleo:     "NextTraceDemo",
}

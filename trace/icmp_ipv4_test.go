package trace

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestICMPIPv4Concurrent(t *testing.T) {
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			tracer := &ICMPTracer{Config: Config{
				SrcAddr:          "",
				BeginHop:         1,
				MaxHops:          30,
				NumMeasurements:  3, // 发送几个测试包
				ParallelRequests: 18,
				Timeout:          5 * time.Second,
				DestPort:         33434,
				Quic:             false,
				RDns:             true,
				AlwaysWaitRDNS:   false,
				PacketInterval:   100,
				TTLInterval:      500,
				Lang:             "cn",
				DN42:             false,
				RealtimePrinter:  nil,
				AsyncPrinter:     nil,
				PktSize:          60,
				Maptrace:         false,
				DestIP:           net.IPv4(8, 8, 8, 8),
			}}
			r2, err := tracer.Execute()
			if err != nil {
				panic(err)
			}
			fmt.Printf("%d ================> %v\n", index, r2.Hops)
		}(i)
	}
	wg.Wait()
}

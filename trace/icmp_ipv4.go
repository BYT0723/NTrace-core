package trace

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/BYT0723/NTrace-core/trace/internal"
)

type ICMPTracer struct {
	Config
	wg              sync.WaitGroup
	res             Result
	ctx             context.Context
	inflightRequest sync.Map
	icmpListen      net.PacketConn
	final           int
	finalLock       sync.Mutex
	fetchLock       sync.Mutex
	id              uint32
}

var (
	idCounter uint32
	id2tracer sync.Map // uint32 -> *ICMPTracer
)

func (t *ICMPTracer) PrintFunc() {
	defer t.wg.Done()
	ttl := t.Config.BeginHop - 1
	for {
		if t.AsyncPrinter != nil {
			t.AsyncPrinter(&t.res)
		}
		// 接收的时候检查一下是不是 3 跳都齐了
		if len(t.res.Hops)-1 > ttl {
			if len(t.res.Hops[ttl]) == t.NumMeasurements {
				if t.RealtimePrinter != nil {
					t.RealtimePrinter(&t.res, ttl)
				}
				ttl++

				if ttl == t.final-1 || ttl >= t.MaxHops-1 {
					return
				}
			}
		}
		<-time.After(200 * time.Millisecond)
	}
}

func (t *ICMPTracer) Execute() (*Result, error) {
	waitTimer := time.NewTimer(max(t.IdRepeatedWait, 5*time.Second))
	t.id = atomic.AddUint32(&idCounter, 1) & 0x3ff
out:
	for {
		select {
		case <-waitTimer.C:
			return &t.res, ErrRepeatedTracerId
		default:
			if _, load := id2tracer.LoadOrStore(t.id, t); !load {
				break out
			}
		}
	}
	defer id2tracer.Delete(t.id)

	if len(t.res.Hops) > 0 {
		return &t.res, ErrTracerouteExecuted
	}

	var err error

	t.icmpListen, err = internal.ListenICMP("ip4:1", t.SrcAddr)
	if err != nil {
		return &t.res, err
	}
	defer t.icmpListen.Close()

	var cancel context.CancelFunc
	t.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	t.final = -1

	go t.listenICMP()
	t.wg.Add(1)
	go t.PrintFunc()
	for ttl := t.BeginHop; ttl <= t.MaxHops; ttl++ {
		t.inflightRequest.Store(ttl, make(chan Hop, t.NumMeasurements*10))
		if t.final != -1 && ttl > t.final {
			break
		}
		for i := 0; i < t.NumMeasurements; i++ {
			t.wg.Add(1)
			go t.send(ttl)
			<-time.After(time.Millisecond * time.Duration(t.Config.PacketInterval))
		}
		<-time.After(time.Millisecond * time.Duration(t.Config.TTLInterval))
	}
	t.wg.Wait()
	t.res.reduce(t.final)
	if t.final != -1 {
		if t.RealtimePrinter != nil {
			t.RealtimePrinter(&t.res, t.final-1)
		}
	} else {
		for i := 0; i < t.NumMeasurements; i++ {
			t.res.add(Hop{
				Success: false,
				Address: nil,
				TTL:     30,
				RTT:     0,
				Error:   ErrHopLimitTimeout,
			})
		}
		if t.RealtimePrinter != nil {
			t.RealtimePrinter(&t.res, t.MaxHops-1)
		}
	}
	return &t.res, nil
}

func (t *ICMPTracer) listenICMP() {
	lc := NewPacketListener(t.icmpListen, t.ctx)
	go lc.Start()
	for {
		select {
		case <-t.ctx.Done():
			return
		case msg := <-lc.Messages:
			if msg.N == nil {
				continue
			}

			var (
				packet_id uint16
				ttl       int64
				dstip     net.IP
			)

			if msg.Msg[0] == 0 {
				packet_id = binary.BigEndian.Uint16(msg.Msg[4:6])
				ttl = int64(binary.BigEndian.Uint16(msg.Msg[6:8]))
				dstip = net.ParseIP(msg.Peer.String())
			} else {
				packet_id = binary.BigEndian.Uint16(msg.Msg[32:34])
				ttl = int64(binary.BigEndian.Uint16(msg.Msg[34:36]))
				dstip = net.IP(msg.Msg[24:28])
			}

			process_id, tracerId, err := reverseID(packet_id)
			if err != nil || process_id != uint32(os.Getpid()&1) {
				continue
			}

			value, ok := id2tracer.Load(tracerId)
			if !ok {
				continue
			}
			rt := value.(*ICMPTracer) // real tracer

			if dstip.Equal(rt.DestIP) || dstip.Equal(net.IPv4zero) {
				// 匹配再继续解析包，否则直接丢弃
				rm, err := icmp.ParseMessage(1, msg.Msg[:*msg.N])
				if err != nil {
					log.Println(err)
					continue
				}

				switch rm.Type {
				case ipv4.ICMPTypeTimeExceeded:
					rt.handleICMPMessage(msg, 0, rm.Body.(*icmp.TimeExceeded).Data, int(ttl))
				case ipv4.ICMPTypeEchoReply:
					rt.handleICMPMessage(msg, 1, rm.Body.(*icmp.Echo).Data, int(ttl))
				// unreachable
				case ipv4.ICMPTypeDestinationUnreachable:
					rt.handleICMPMessage(msg, 2, rm.Body.(*icmp.DstUnreach).Data, int(ttl))
				default:
					// log.Println("received icmp message of unknown type", rm.Type)
				}
			}
		}
	}
}

func (t *ICMPTracer) handleICMPMessage(msg ReceivedMessage, icmpType int8, data []byte, ttl int) {
	if icmpType == 2 {
		if t.DestIP.String() != msg.Peer.String() {
			return
		}
	}

	mpls := extractMPLS(msg, data, t.Config.PktSize)

	if v, ok := t.inflightRequest.Load(ttl); ok && v != nil {
		if ch, ok := v.(chan Hop); ok {
			ch <- Hop{
				Success: true,
				Address: msg.Peer,
				MPLS:    mpls,
			}
		}
	}
}

func gernerateID(tracerId uint32, ttl_int int, flag_int int) uint16 {
	var (
		flag   = uint16(flag_int & 1)      // flag 1bit
		tracer = uint16(tracerId & 0x03ff) // tracer id 11bit
		ttl    = uint16(ttl_int & 0x1f)    // ttl index 5bit
	)
	id := flag<<15 | tracer<<5 | ttl
	return id
}

func reverseID(id uint16) (flag, tracerId uint32, err error) {
	flag = uint32(id >> 15 & 1)
	tracerId = uint32(id >> 5 & 0x03ff)
	return
}

func (t *ICMPTracer) send(ttl int) error {
	defer t.wg.Done()
	if t.final != -1 && ttl > t.final {
		return nil
	}

	id := gernerateID(t.id, ttl, t.Collector)
	// log.Println("发送的", id)

	data := []byte{byte(ttl)}
	data = append(data, bytes.Repeat([]byte{1}, t.Config.PktSize-5)...)
	data = append(data, 0x00, 0x00, 0x4f, 0xff)

	icmpHeader := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: int(id),
			// Data: []byte("HELLO-R-U-THERE"),
			Data: data,
			Seq:  ttl,
		},
	}

	ipv4.NewPacketConn(t.icmpListen).SetTTL(ttl)

	wb, err := icmpHeader.Marshal(nil)
	if err != nil {
		panic(err)
	}

	start := time.Now()
	if _, err := t.icmpListen.WriteTo(wb, &net.IPAddr{IP: t.DestIP}); err != nil {
		panic(err)
	}
	if err := t.icmpListen.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		panic(err)
	}
	value, _ := t.inflightRequest.Load(ttl)
	select {
	case <-t.ctx.Done():
		return nil
	case h := <-value.(chan Hop):
		rtt := time.Since(start)
		if t.final != -1 && ttl > t.final {
			return nil
		}
		if addr, ok := h.Address.(*net.IPAddr); ok && addr.IP.Equal(t.DestIP) {
			t.finalLock.Lock()
			if t.final == -1 || ttl < t.final {
				t.final = ttl
			}
			t.finalLock.Unlock()
		} else if addr, ok := h.Address.(*net.TCPAddr); ok && addr.IP.Equal(t.DestIP) {
			t.finalLock.Lock()
			if t.final == -1 || ttl < t.final {
				t.final = ttl
			}
			t.finalLock.Unlock()
		}

		h.TTL = ttl
		h.RTT = rtt

		t.fetchLock.Lock()
		defer t.fetchLock.Unlock()
		h.fetchIPData(t.Config)

		t.res.add(h)
	case <-time.After(t.Timeout):
		if t.final != -1 && ttl > t.final {
			return nil
		}

		t.res.add(Hop{
			Success: false,
			Address: nil,
			TTL:     ttl,
			RTT:     0,
			Error:   ErrHopLimitTimeout,
		})

	}

	return nil
}

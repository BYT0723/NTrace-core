package trace

import (
	"bytes"
	"encoding/binary"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"github.com/BYT0723/NTrace-core/trace/internal"
	"golang.org/x/net/context"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ICMPTracer struct {
	Config
	wg              sync.WaitGroup
	res             Result
	ctx             context.Context
	cf              context.CancelFunc
	inflightRequest []chan Hop
	final           int
	finalLock       sync.Mutex
	fetchLock       sync.Mutex
	id              uint32
}

var (
	idPool         chan uint32
	id2tracer      map[uint32]*ICMPTracer
	id2tracerMutex sync.Mutex

	listenInit    sync.Once
	listenerMutex sync.Mutex
	listener      net.PacketConn
)

func init() {
	n := math.MaxUint32 & 0x7fff
	idPool = make(chan uint32, n)
	for i := range n {
		idPool <- uint32(i)
	}
	id2tracer = make(map[uint32]*ICMPTracer)
}

func (t *ICMPTracer) PrintFunc() {
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
	listenInit.Do(func() {
		t.listenICMP(context.Background())
	})

	// 生成 id
	select {
	case t.id = <-idPool:
	case <-time.After(t.IdRepeatedWait):
		return &t.res, ErrRepeatedTracerId
	}

	// 保存
	id2tracerMutex.Lock()
	id2tracer[t.id] = t
	id2tracerMutex.Unlock()

	defer func() {
		idPool <- t.id
		id2tracerMutex.Lock()
		delete(id2tracer, t.id)
		id2tracerMutex.Unlock()
	}()

	if len(t.res.Hops) > 0 {
		return &t.res, ErrTracerouteExecuted
	}

	t.ctx, t.cf = context.WithCancel(context.Background())
	defer t.cf()
	t.final = -1
	t.inflightRequest = make([]chan Hop, t.MaxHops)

	go t.PrintFunc()

	for ttl := t.BeginHop; ttl <= t.MaxHops; ttl++ {
		t.inflightRequest[ttl-1] = make(chan Hop, t.NumMeasurements)
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

func (t *ICMPTracer) listenICMP(ctx context.Context) {
	var err error

	for listener == nil {
		listener, err = internal.ListenICMP("ip4:1", "")
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
	}
	lc := NewPacketListener(listener, ctx)
	go lc.Start()
	go func() {
		for {
			select {
			case <-ctx.Done():
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

				flag, tracerId := reverseID(packet_id)
				if flag != uint32(t.Collector&1) {
					continue
				}

				id2tracerMutex.Lock()
				rt, ok := id2tracer[tracerId]
				id2tracerMutex.Unlock()
				if !ok {
					continue
				}

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
	}()
}

func (t *ICMPTracer) handleICMPMessage(msg ReceivedMessage, icmpType int8, data []byte, ttl int) {
	if icmpType == 2 {
		if t.DestIP.String() != msg.Peer.String() {
			return
		}
	}

	mpls := extractMPLS(msg, data, t.Config.PktSize)

	t.inflightRequest[ttl-1] <- Hop{
		Success: true,
		Address: msg.Peer,
		MPLS:    mpls,
	}
}

func generateID(tracerId uint32, flag_int int) uint16 {
	var (
		flag   = uint16(flag_int & 1)      // flag 1bit
		tracer = uint16(tracerId & 0x7fff) // tracer id 11bit
	)
	id := flag<<15 | tracer
	return id
}

func reverseID(id uint16) (flag, tracerId uint32) {
	flag = uint32(id >> 15 & 1)
	tracerId = uint32(id & 0x7fff)
	return flag, tracerId
}

func (t *ICMPTracer) send(ttl int) error {
	defer t.wg.Done()
	if t.final != -1 && ttl > t.final {
		return nil
	}

	id := generateID(t.id, t.Collector)
	// log.Println("发送的", id)

	data := []byte{byte(ttl)}
	data = append(data, bytes.Repeat([]byte{1}, t.Config.PktSize-5)...)
	data = append(data, 0x00, 0x00, 0x4f, 0xff)

	icmpHeader := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Data: data,
			Seq:  ttl,
		},
	}

	wb, err := icmpHeader.Marshal(nil)
	if err != nil {
		return err
	}

	listenerMutex.Lock()
	ipv4.NewPacketConn(listener).SetTTL(ttl)
	start := time.Now()
	if _, err := listener.WriteTo(wb, &net.IPAddr{IP: t.DestIP}); err != nil {
		return err
	}
	listenerMutex.Unlock()

	select {
	case <-t.ctx.Done():
		return nil
	case h := <-t.inflightRequest[ttl-1]:
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

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"flag"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	tls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
)

const (
	PORT   = "7878"
	COUNT  = 5
	DEGREE = 2

	msgSize = 2 * 1 << 20

	Dlo = 6
	D   = 8
	Dhi = 12
)

var (
	countFlag  = flag.Int("count", COUNT, "the number of nodes in the network")
	degreeFlag = flag.Int("degree", DEGREE, "the number of connected nodes")
)

func resolveHostname(hname string) (string, error) {
	ips, err := net.LookupIP(hname)

	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", errors.New("Couldn't resolve hostname")
}

// creates a custom gossipsub parameter set.
func pubsubGossipParam() pubsub.GossipSubParams {
	gParams := pubsub.DefaultGossipSubParams()
	gParams.Dlo = Dlo
	gParams.D = D
	gParams.Dhi = Dhi
	gParams.HeartbeatInterval = 700 * time.Millisecond
	gParams.HistoryLength = 6
	gParams.HistoryGossip = 3
	return gParams
}

// pubsubOptions creates a list of options to configure our router with.
func pubsubOptions() []pubsub.Option {
	psOpts := []pubsub.Option{
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithNoAuthor(),
		pubsub.WithPeerOutboundQueueSize(600),
		pubsub.WithMaxMessageSize(10 * 1 << 20),
		pubsub.WithValidateQueueSize(600),
		pubsub.WithGossipSubParams(pubsubGossipParam()),
	}

	return psOpts
}

func convToPrivKey(input string) (crypto.PrivKey, error) {
	hash := sha256.New()
	hash.Write([]byte(input))
	seed := hash.Sum(nil)

	priv := ed25519.NewKeyFromSeed(seed)
	privKey, err := crypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func getPeerID(input string) peer.ID {
	privKey, err := convToPrivKey(input)
	if err != nil {
		panic(err)
	}

	// Convert the hash to a peer.ID
	peerID, err := peer.IDFromPrivateKey(privKey)
	if err != nil {
		panic(err)
	}

	return peerID
}

func publish(ctx context.Context, t *pubsub.Topic, data []byte, opts ...pubsub.PubOpt) error {
	// Wait for at least 1 peer to be available to receive the published message.
	for {
		if len(t.ListPeers()) > 0 {
			return t.Publish(ctx, data, opts...)
		}

		select {
		case <-ctx.Done():
			return errors.New("unable to find requisite number of peers, 0 peers found to publish to")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func leave(t *pubsub.Topic) error {
	if err := t.Close(); err != nil {
		return err
	}
	return nil
}

func connectToRandomPeers(ctx context.Context, h host.Host, num int) int {
	rand.Seed(time.Now().UnixNano())

	var connected atomic.Uint64
	var wg sync.WaitGroup
	for i := 0; i < num; i++ {
		hname := "node" + strconv.Itoa(rand.Intn(*countFlag)+1)
		ip, err := resolveHostname(hname)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("Resolved %s to %s\n", hname, ip)

		maddr := "/ip4/" + ip + "/tcp/" + PORT + "/p2p/" + getPeerID(hname).String()
		info, err := peer.AddrInfoFromString(maddr)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Printf("Connecting to %s\n", maddr)

		// make each dial non-blocking
		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if err := h.Connect(ctx, pi); err != nil {
				fmt.Println("couldn't dial ", pi.Addrs)
			}
			connected.Add(1)
		}(*info)
	}
	wg.Wait()
	return int(connected.Load())
}

func main() {
	fmt.Println("Starting a node")

	flag.Parse()
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Hostname: %s\n", hostname)
	fmt.Printf("Count: %d\n", *countFlag)
	fmt.Printf("Degree: %d\n", *degreeFlag)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transports := libp2p.ChainOptions(
		libp2p.Transport(tcp.NewTCPTransport),
	)

	muxers := libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport)
	security := libp2p.Security(tls.ID, tls.New)
	listenAddrs := libp2p.ListenAddrStrings(
		"/ip4/0.0.0.0/tcp/" + PORT,
	)

	privKey, err := convToPrivKey(hostname)
	if err != nil {
		panic(err)
	}

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		transports,
		listenAddrs,
		muxers,
		security,
	)
	defer h.Close()

	if err != nil {
		panic(err)
	}

	fmt.Println("Enabling GossipSub")
	psOpts := pubsubOptions()
	gs, err := pubsub.NewGossipSub(ctx, h, psOpts...)

	nConnected := connectToRandomPeers(ctx, h, *degreeFlag)
	fmt.Printf("Connected to %d Peers\n", nConnected)

	var tOpts []pubsub.TopicOpt
	topicHandle, err := gs.Join("simulate", tOpts...)

	if err != nil {
		panic(err)
	}

	if hostname == "node0" {
		var pOpts []pubsub.PubOpt
		msg := make([]byte, msgSize)
		rand.Read(msg)
		err = publish(ctx, topicHandle, msg, pOpts...)
		if err != nil {
			panic(err)
		}
	} else {
		var sOpts []pubsub.SubOpt
		subHandle, err := topicHandle.Subscribe(sOpts...)
		if err != nil {
			panic(err)
		}
		// readLoop pulls messages from the pubsub topic and pushes them onto the Messages channel.
		go func(ctx context.Context, subHandle *pubsub.Subscription, ho host.Host) {
			for {
				msg, err := subHandle.Next(ctx)

				if err != nil {
					fmt.Println("Error reading from subscription")
					return
				}

				// only forward messages delivered by others
				if msg.ReceivedFrom == ho.ID() {
					continue
				}

				// send valid messages onto the Messages channel
				if len(msg.Data) > 0 {
					fmt.Printf("Received Message of Size %d\n", len(msg.Data))
				}
			}
		}(ctx, subHandle, h)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT)

	<-stop
	fmt.Println("Received signal, shutting down...")
}

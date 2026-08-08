package network

import (
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/evilsocket/islazy/data"
)

func Dot11Freq2Chan(freq int) int {
	switch {
	case freq <= 2472:
		return ((freq - 2412) / 5) + 1

	case freq == 2484:
		return 14

	case freq >= 5035 && freq <= 5865:
		return ((freq - 5035) / 5) + 7

	case freq >= 5875 && freq <= 5895:
		return 177

	case freq >= 5955 && freq <= 7115: // 6GHz
		return ((freq - 5955) / 5) + 1
	}

	return 0
}

var dot11Channel5GHz = map[int]struct{}{
	36:  {}, 40:  {}, 44:  {}, 48:  {},
	52:  {}, 56:  {}, 60:  {}, 64:  {},

	68:  {}, 72:  {}, 76:  {}, 80:  {},
	100: {}, 104: {}, 108: {}, 112: {},

	116: {}, 120: {}, 124: {}, 128: {},
	132: {}, 136: {}, 140: {}, 144: {},

	149: {}, 153: {}, 157: {}, 161: {},
	165: {}, 169: {}, 173: {}, 177: {},
}

func Dot11Chan2Freq(channel int) int {
	if channel <= 13 {
		return ((channel - 1) * 5) + 2412
	}

	if channel == 14 {
		return 2484
	}

	if _, ok := dot11Channel5GHz[channel]; ok {
		return ((channel - 7) * 5) + 5035
	}
	
	// 6GHz - Skipped 1-13 to avoid 2Ghz channels conflict
	if channel >= 17 && channel <= 253 {
		return ((channel - 1) * 5) + 5955
	}

	return 0
}

type APNewCallback func(ap *AccessPoint)
type APLostCallback func(ap *AccessPoint)

type WiFi struct {
	sync.RWMutex

	aliases *data.UnsortedKV
	aps     map[string]*AccessPoint
	iface   *Endpoint
	newCb   APNewCallback
	lostCb  APLostCallback

	shakesLock    sync.Mutex
	shakesWriters map[string]*ngHandshakeWriter
}

// ngHandshakeWriter holds a persistent pcapng writer for one handshake
// output file, kept open for the life of the process instead of being
// reopened (and writing a brand new section) on every single packet.
// Reopening per-packet is what causes the pcapng interface count to climb
// past hcxpcapngtool's 255-interface cap on long-running captures.
type ngHandshakeWriter struct {
	file   *os.File
	writer *pcapgo.NgWriter
	// seen dedups by content checksum at the point of writing to *this
	// file*, not per-station: the AP's own beacon frame (captured once,
	// early) gets copied into every new client's own Handshake.unsaved
	// queue (see discoverHandshakes, "adding beacon frame to handshake"),
	// so a per-station dedup only catches a station re-sending its own
	// copy - it doesn't catch a second, different client re-injecting
	// that same early-timestamped beacon after later data has already
	// been written, which reintroduces the "out of sequence" ordering
	// this whole file is trying to avoid.
	seen map[uint32]struct{}
	// lastTS is the timestamp of the last packet actually written to this
	// file. Per-call sorting only orders packets *within* one save; it
	// can't fix a genuinely different (non-duplicate) frame that was
	// queued early into some quiet client's own unsaved buffer via
	// AddExtra and only gets flushed much later, once that specific
	// client finally has another triggering event - by which point
	// *other, busier* clients of the same AP have already pushed this
	// file's timestamps well past it. Clamping to a running monotonic
	// floor fixes that cross-call, cross-client case: it doesn't lose any
	// EAPOL/crypto content (that lives in the packet payload, not the
	// timestamp), it just keeps the file's timestamp column monotonic,
	// which is all hcxpcapngtool's check actually requires.
	lastTS time.Time
}

type wifiJSON struct {
	AccessPoints []*AccessPoint `json:"aps"`
}

func NewWiFi(iface *Endpoint, aliases *data.UnsortedKV, newcb APNewCallback, lostcb APLostCallback) *WiFi {
	return &WiFi{
		aps:     make(map[string]*AccessPoint),
		aliases: aliases,
		iface:   iface,
		newCb:   newcb,
		lostCb:  lostcb,
	}
}

func (w *WiFi) MarshalJSON() ([]byte, error) {

	doc := wifiJSON{
		// we know the length so preallocate to reduce memory allocations
		AccessPoints: make([]*AccessPoint, 0, len(w.aps)),
	}

	for _, ap := range w.aps {
		doc.AccessPoints = append(doc.AccessPoints, ap)
	}

	return json.Marshal(doc)
}

func (w *WiFi) EachAccessPoint(cb func(mac string, ap *AccessPoint)) {
	w.Lock()
	defer w.Unlock()

	for m, ap := range w.aps {
		cb(m, ap)
	}
}

func (w *WiFi) Stations() (list []*Station) {
	w.RLock()
	defer w.RUnlock()

	list = make([]*Station, 0, len(w.aps))

	for _, ap := range w.aps {
		list = append(list, ap.Station)
	}
	return
}

func (w *WiFi) List() (list []*AccessPoint) {
	w.RLock()
	defer w.RUnlock()

	list = make([]*AccessPoint, 0, len(w.aps))

	for _, ap := range w.aps {
		list = append(list, ap)
	}
	return
}

func (w *WiFi) Remove(mac string) {
	w.Lock()
	defer w.Unlock()

	if ap, found := w.aps[mac]; found {
		delete(w.aps, mac)
		if w.lostCb != nil {
			w.lostCb(ap)
		}
	}
}

// when iface is in monitor mode, error
// correction on macOS is crap and we
// get non printable characters .... (ref #61)
func isBogusMacESSID(essid string) bool {
	for _, c := range essid {
		if !strconv.IsPrint(c) {
			return true
		}
	}
	return false
}

func (w *WiFi) AddIfNew(ssid, mac string, frequency int, rssi int8) (*AccessPoint, bool) {
	w.Lock()
	defer w.Unlock()

	mac = NormalizeMac(mac)
	alias := w.aliases.GetOr(mac, "")
	if ap, found := w.aps[mac]; found {
		ap.LastSeen = time.Now()
		if rssi != 0 {
			ap.RSSI = rssi
		}
		// always get the cleanest one
		if !isBogusMacESSID(ssid) {
			ap.Hostname = ssid
		}

		if alias != "" {
			ap.Alias = alias
		}
		return ap, false
	}

	newAp := NewAccessPoint(ssid, mac, frequency, rssi, w.aliases)
	newAp.Alias = alias
	w.aps[mac] = newAp

	if w.newCb != nil {
		w.newCb(newAp)
	}

	return newAp, true
}

func (w *WiFi) Get(mac string) (*AccessPoint, bool) {
	w.RLock()
	defer w.RUnlock()

	mac = NormalizeMac(mac)
	ap, found := w.aps[mac]
	return ap, found
}

func (w *WiFi) GetClient(mac string) (*Station, bool) {
	w.RLock()
	defer w.RUnlock()

	mac = NormalizeMac(mac)
	for _, ap := range w.aps {
		if client, found := ap.Get(mac); found {
			return client, true
		}
	}

	return nil, false
}

func (w *WiFi) Clear() {
	w.Lock()
	defer w.Unlock()
	w.aps = make(map[string]*AccessPoint)
}

func (w *WiFi) NumAPs() int {
	w.RLock()
	defer w.RUnlock()

	return len(w.aps)
}

func (w *WiFi) NumHandshakes() int {
	w.RLock()
	defer w.RUnlock()

	sum := 0
	for _, ap := range w.aps {
		for _, station := range ap.Clients() {
			if station.Handshake.Complete() {
				sum++
			}
		}
	}

	return sum
}

type pendingHandshakePacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

func (w *WiFi) SaveHandshakesTo(ap *AccessPoint, fileName string, linkType layers.LinkType) error {
	hw, err := w.getHandshakeWriter(fileName, linkType)
	if err != nil {
		return err
	}

	// Collect first, write after: ap.Clients() is a map, and Go randomizes
	// map iteration order on every pass. Writing straight from that loop
	// interleaves different stations' (already-chronological) packet runs
	// in random order, which is what was producing pcapng's "out of
	// sequence timestamps" warning - not a capture-timing issue.
	//
	// Scoped to just this ap's clients - this used to iterate every AP in
	// w.aps regardless of which one fileName belongs to, so any AP's save
	// would drain (EachUnsavedPacket empties the buffer) and write every
	// *other* AP's pending packets too, mixing unrelated networks into a
	// single AP's capture file and making "out of sequence" effectively
	// unfixable at the write-ordering level alone.
	var pending []pendingHandshakePacket

	w.RLock()
	for _, station := range ap.Clients() {
		// if half (which includes also complete) or has pmkid
		if station.Handshake.Any() {
			station.Handshake.EachUnsavedPacket(func(pkt gopacket.Packet) {
				ci := pkt.Metadata().CaptureInfo
				ci.InterfaceIndex = 0
				pending = append(pending, pendingHandshakePacket{ci: ci, data: pkt.Data()})
			})
		}
	}
	w.RUnlock()

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].ci.Timestamp.Before(pending[j].ci.Timestamp)
	})

	for _, p := range pending {
		sum := crc32.ChecksumIEEE(p.data)
		if _, dup := hw.seen[sum]; dup {
			continue
		}
		if !hw.lastTS.IsZero() && p.ci.Timestamp.Before(hw.lastTS) {
			p.ci.Timestamp = hw.lastTS.Add(time.Nanosecond)
		}
		if err := hw.writer.WritePacket(p.ci, p.data); err != nil {
			return err
		}
		hw.lastTS = p.ci.Timestamp
		hw.seen[sum] = struct{}{}
	}

	return hw.writer.Flush()
}

// lastPcapngPacketTimestamp reads through every packet in an existing
// pcapng file to find the timestamp of the last one written, so a resumed
// capture can keep its monotonic timestamp guarantee across the boundary
// between one process run's packets and the next's. ok is only true if the
// file parsed cleanly through to a real EOF - any other error means the
// file may be truncated or corrupted, and the caller falls back to
// starting a fresh section rather than risking an invalid append.
func lastPcapngPacketTimestamp(fileName string) (ts time.Time, ok bool) {
	fp, err := os.Open(fileName)
	if err != nil {
		return ts, false
	}
	defer fp.Close()

	reader, err := pcapgo.NewNgReader(fp, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return ts, false
	}

	found := false
	for {
		_, ci, err := reader.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return ts, false
		}
		ts = ci.Timestamp
		found = true
	}
	return ts, found
}

// getHandshakeWriter returns the persistent pcapng writer for fileName,
// opening and registering it the first time it's requested.
func (w *WiFi) getHandshakeWriter(fileName string, linkType layers.LinkType) (*ngHandshakeWriter, error) {
	w.shakesLock.Lock()
	defer w.shakesLock.Unlock()

	if hw, found := w.shakesWriters[fileName]; found {
		return hw, nil
	}

	// check if folder exists first
	dirName := filepath.Dir(fileName)
	if _, err := os.Stat(dirName); err != nil {
		if err = os.MkdirAll(dirName, os.ModePerm); err != nil {
			return nil, err
		}
	}

	// a prior process run may have already written a section to this file
	// (pwnagotchi restarting between handshakes is routine) - if so, seed
	// lastTS from its last packet and append into that section instead of
	// starting a brand new one, otherwise "used capture interfaces" grows
	// by one on every restart, recreating the same interface-count blowup
	// the persistent-writer fix solved for per-packet reopens, just
	// triggered by process restarts instead.
	var lastTS time.Time
	appendExisting := false
	if stat, err := os.Stat(fileName); err == nil && stat.Size() > 0 {
		if last, ok := lastPcapngPacketTimestamp(fileName); ok {
			lastTS = last
			appendExisting = true
		}
	}

	fp, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	opts := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    runtime.GOARCH,
			OS:          runtime.GOOS,
			Application: "Pwnagotchi",
		},
	}

	var writer *pcapgo.NgWriter
	if appendExisting {
		writer = pcapgo.NewNgWriterAppendInterface(fp, opts)
	} else {
		intf := pcapgo.DefaultNgInterface
		intf.LinkType = linkType
		if writer, err = pcapgo.NewNgWriterInterface(fp, intf, opts); err != nil {
			fp.Close()
			return nil, err
		}
	}

	hw := &ngHandshakeWriter{file: fp, writer: writer, seen: make(map[uint32]struct{}), lastTS: lastTS}
	if w.shakesWriters == nil {
		w.shakesWriters = make(map[string]*ngHandshakeWriter)
	}
	w.shakesWriters[fileName] = hw
	return hw, nil
}

// CloseHandshakeWriters flushes and closes every open handshake pcapng
// writer. Must be called on session/module shutdown so file handles don't
// leak and the last written packets are actually flushed to disk.
func (w *WiFi) CloseHandshakeWriters() {
	w.shakesLock.Lock()
	defer w.shakesLock.Unlock()

	for fileName, hw := range w.shakesWriters {
		hw.writer.Flush()
		hw.file.Close()
		delete(w.shakesWriters, fileName)
	}
}

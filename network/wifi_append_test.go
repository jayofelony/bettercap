package network

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// TestHandshakeWriterAppendAcrossRestart simulates two separate process
// runs writing to the same handshake file (a fresh *WiFi per run, same
// fileName), which is what happens on every pwnagotchi restart between
// handshakes. It must not add a second pcapng section/interface, and the
// second run's writer must pick up lastTS from the first run's last packet.
func TestHandshakeWriterAppendAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	fileName := filepath.Join(dir, "test.pcapng")

	data := []byte{1, 2, 3, 4}
	ci1 := gopacket.CaptureInfo{
		Timestamp:     time.Now().Truncate(time.Second),
		CaptureLength: len(data),
		Length:        len(data),
	}

	w1 := &WiFi{}
	hw1, err := w1.getHandshakeWriter(fileName, layers.LinkTypeIEEE80211Radio)
	if err != nil {
		t.Fatalf("run1 getHandshakeWriter: %v", err)
	}
	if err := hw1.writer.WritePacket(ci1, data); err != nil {
		t.Fatalf("run1 WritePacket: %v", err)
	}
	w1.CloseHandshakeWriters()

	ci2 := ci1
	ci2.Timestamp = ci1.Timestamp.Add(time.Second)

	w2 := &WiFi{}
	hw2, err := w2.getHandshakeWriter(fileName, layers.LinkTypeIEEE80211Radio)
	if err != nil {
		t.Fatalf("run2 getHandshakeWriter: %v", err)
	}
	if !hw2.lastTS.Equal(ci1.Timestamp) {
		t.Fatalf("run2 lastTS = %v, want %v (run1's last packet timestamp)", hw2.lastTS, ci1.Timestamp)
	}
	if err := hw2.writer.WritePacket(ci2, data); err != nil {
		t.Fatalf("run2 WritePacket: %v", err)
	}
	w2.CloseHandshakeWriters()

	fp, err := os.Open(fileName)
	if err != nil {
		t.Fatalf("open result file: %v", err)
	}
	defer fp.Close()

	reader, err := pcapgo.NewNgReader(fp, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader: %v", err)
	}

	packets := 0
	var timestamps []time.Time
	for {
		_, ci, err := reader.ZeroCopyReadPacketData()
		if err != nil {
			break
		}
		packets++
		timestamps = append(timestamps, ci.Timestamp)
	}

	if packets != 2 {
		t.Fatalf("got %d packets, want 2", packets)
	}
	if n := reader.NInterfaces(); n != 1 {
		t.Fatalf("got %d interfaces after traversing the whole file, want 1 (this is the bug: every restart used to add a new section+interface)", n)
	}
	if !timestamps[1].After(timestamps[0]) {
		t.Fatalf("timestamps not monotonic across the restart boundary: %v then %v", timestamps[0], timestamps[1])
	}
}

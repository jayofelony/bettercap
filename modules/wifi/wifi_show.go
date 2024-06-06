package wifi

import (
	"fmt"
	"github.com/jayofelony/bettercap/network"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/evilsocket/islazy/ops"
	"github.com/evilsocket/islazy/tui"
)

func (mod *WiFiModule) isApSelected() bool {
	return mod.ap != nil
}

func (mod *WiFiModule) getRow(station *network.Station) ([]string, bool) {
	rssi := network.ColorRSSI(int(station.RSSI))
	bssid := station.HwAddress
	bssid = tui.Bold(bssid)

	seen := station.LastSeen.Format("15:04:05")
	seen = tui.Bold(seen)
	ssid := ops.Ternary(station.ESSID() == "<hidden>", tui.Dim(station.ESSID()), station.ESSID()).(string)

	encryption := station.Encryption
	if len(station.Cipher) > 0 {
		encryption = fmt.Sprintf("%s (%s, %s)", station.Encryption, station.Cipher, station.Authentication)
	}

	if encryption == "OPEN" || encryption == "" {
		encryption = tui.Green("OPEN")
		ssid = tui.Green(ssid)
		bssid = tui.Green(bssid)
	} else {
		// this is ugly, but necessary in order to have this
		// method handle both access point and clients
		// transparently
		if ap, found := mod.Session.WiFi.Get(station.HwAddress); found && ap.HasKeyMaterial() {
			encryption = tui.Red(encryption)
		}
	}

	sent := ops.Ternary(station.Sent > 0, humanize.Bytes(station.Sent), "").(string)
	recvd := ops.Ternary(station.Received > 0, humanize.Bytes(station.Received), "").(string)

	include := false
	if mod.source == "" {
		for _, frequencies := range mod.frequencies {
			if frequencies == station.Frequency {
				include = true
				break
			}
		}
	} else {
		include = true
	}

	if int(station.RSSI) < mod.minRSSI {
		include = false
	}

	if mod.isApSelected() {
		if mod.showManuf {
			return []string{
				rssi,
				bssid,
				tui.Dim(station.Vendor),
				strconv.Itoa(station.Channel),
				sent,
				recvd,
				seen,
			}, include
		} else {
			return []string{
				rssi,
				bssid,
				strconv.Itoa(station.Channel),
				sent,
				recvd,
				seen,
			}, include
		}
	} else {
		// this is ugly, but necessary in order to have this
		// method handle both access point and clients
		// transparently
		clients := ""
		if ap, found := mod.Session.WiFi.Get(station.HwAddress); found {
			if ap.NumClients() > 0 {
				clients = strconv.Itoa(ap.NumClients())
			}
		}

		wps := ""
		if station.HasWPS() {
			if ver, found := station.WPS["Version"]; found {
				wps = ver
			} else {
				wps = "✔"
			}

			if state, found := station.WPS["State"]; found {
				if state == "Not Configured" {
					wps += " (not configured)"
				}
			}

			wps = tui.Dim(tui.Yellow(wps))
		}

		if mod.showManuf {
			return []string{
				rssi,
				bssid,
				tui.Dim(station.Vendor),
				ssid,
				encryption,
				wps,
				strconv.Itoa(station.Channel),
				clients,
				sent,
				recvd,
				seen,
			}, include
		} else {
			return []string{
				rssi,
				bssid,
				ssid,
				encryption,
				wps,
				strconv.Itoa(station.Channel),
				clients,
				sent,
				recvd,
				seen,
			}, include
		}
	}
}

func (mod *WiFiModule) colDecorate(colNames []string, name string, dir string) {
	for i, c := range colNames {
		if c == name {
			colNames[i] += " " + dir
			break
		}
	}
}

func (mod *WiFiModule) showStatusBar() {
	parts := []string{
		fmt.Sprintf("%s (ch. %d)", mod.iface.Name(), network.GetInterfaceChannel(mod.iface.Name())),
		fmt.Sprintf("%s %s", tui.Red("↑"), humanize.Bytes(mod.Session.Queue.Stats.Sent)),
		fmt.Sprintf("%s %s", tui.Green("↓"), humanize.Bytes(mod.Session.Queue.Stats.Received)),
		fmt.Sprintf("%d pkts", mod.Session.Queue.Stats.PktReceived),
	}

	if nErrors := mod.Session.Queue.Stats.Errors; nErrors > 0 {
		parts = append(parts, fmt.Sprintf("%d errs", nErrors))
	}

	if nHandshakes := mod.Session.WiFi.NumHandshakes(); nHandshakes > 0 {
		parts = append(parts, fmt.Sprintf("%d handshakes", nHandshakes))
	}

	mod.Printf("\n%s\n\n", strings.Join(parts, " / "))
}

//go:build windows
// +build windows

package events_stream

import (
	"github.com/jayofelony/bettercap/session"
	"io"
)

func (mod *EventsStream) viewBLEEvent(output io.Writer, e session.Event) {

}

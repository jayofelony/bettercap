package modules

import (
	"github.com/jayofelony/bettercap/modules/api_rest"
	"github.com/jayofelony/bettercap/modules/caplets"
	"github.com/jayofelony/bettercap/modules/events_stream"
	"github.com/jayofelony/bettercap/modules/gps"
	"github.com/jayofelony/bettercap/modules/wifi"

	"github.com/jayofelony/bettercap/session"
)

func LoadModules(sess *session.Session) {
	sess.Register(api_rest.NewRestAPI(sess))
	sess.Register(events_stream.NewEventsStream(sess))
	sess.Register(gps.NewGPS(sess))
	sess.Register(wifi.NewWiFiModule(sess))
	sess.Register(caplets.NewCapletsModule(sess))
}

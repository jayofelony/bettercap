package modules

import (
	"github.com/jayofelony/bettercap/modules/api_rest"
	"github.com/jayofelony/bettercap/modules/ble"
	"github.com/jayofelony/bettercap/modules/caplets"
	"github.com/jayofelony/bettercap/modules/events_stream"
	"github.com/jayofelony/bettercap/modules/gps"
	"github.com/jayofelony/bettercap/modules/http_server"
	"github.com/jayofelony/bettercap/modules/https_server"
	"github.com/jayofelony/bettercap/modules/mysql_server"
	"github.com/jayofelony/bettercap/modules/tcp_proxy"
	"github.com/jayofelony/bettercap/modules/ui"
	"github.com/jayofelony/bettercap/modules/update"
	"github.com/jayofelony/bettercap/modules/wifi"
	"github.com/jayofelony/bettercap/modules/wol"

	"github.com/jayofelony/bettercap/session"
)

func LoadModules(sess *session.Session) {
	sess.Register(api_rest.NewRestAPI(sess))
	sess.Register(ble.NewBLERecon(sess))
	sess.Register(events_stream.NewEventsStream(sess))
	sess.Register(gps.NewGPS(sess))
	sess.Register(http_server.NewHttpServer(sess))
	sess.Register(https_server.NewHttpsServer(sess))
	sess.Register(mysql_server.NewMySQLServer(sess))
	sess.Register(tcp_proxy.NewTcpProxy(sess))
	sess.Register(wifi.NewWiFiModule(sess))
	sess.Register(wol.NewWOL(sess))

	sess.Register(caplets.NewCapletsModule(sess))
	sess.Register(update.NewUpdateModule(sess))
	sess.Register(ui.NewUIModule(sess))
}

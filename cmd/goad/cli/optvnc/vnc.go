package optvnc

import (
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/5amu/goad/pkg/proxyconn"
	"github.com/mitchellh/go-vnc"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Password string `short:"p" description:"Provide password (or FILE)"`
		Port     int    `long:"port" default:"5900" description:"Port to contact"`
	} `group:"Connection Options" description:"Connection Options"`

	printMutex    sync.Mutex
	targets       []string
	credentials   []utils.Credential
	target2Banner map[string]string
}

func (o *Options) Run() {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.credentials = utils.NewCredentialsClusterBomb(
		utils.ExtractLinesFromFileOrString(""),
		utils.ExtractLinesFromFileOrString(o.Connection.Password),
	)
	o.target2Banner = gatherTarget2BannerMap(&o.printMutex, o.targets, o.Connection.Port)

	if !slices.Contains(os.Args, "-p") {
		return
	}

	var wg sync.WaitGroup
	for target := range o.target2Banner {
		wg.Add(1)
		go func(t string) {
			_, _ = o.authenticate(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) authenticate(target string) (utils.Credential, error) {
	prt := printer.NewPrinter("VNC", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	var found bool = false
	var name string
	for _, cred := range o.credentials {
		conn, err := proxyconn.GetConnection(target, o.Connection.Port)
		if err != nil {
			prt.StoreFailure(err.Error())
		}
		c, err := vnc.Client(conn, &vnc.ClientConfig{
			Auth: []vnc.ClientAuth{
				&vnc.PasswordAuth{
					Password: cred.Password,
				},
			},
		})
		if err != nil {
			fmt.Println(err)
			prt.StoreFailure(cred.String())
			continue
		}
		name = c.DesktopName
		go func() {
			_ = c.Close()
		}()
		found = true
		prt.StoreSuccess(cred.String())
	}

	if found {
		prt.StoreInfo(fmt.Sprintf("VNC Desktop Name: %s", name))
		return utils.Credential{}, nil
	}
	return utils.Credential{}, fmt.Errorf("no valid authentication")
}

func gatherTarget2BannerMap(mutex *sync.Mutex, targets []string, port int) map[string]string {
	res := make(map[string]string)
	var mapMutex sync.Mutex

	mutex.Lock()
	defer mutex.Unlock()

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(p string) {
			if VerifyVNC(p, port) {
				prt := printer.NewPrinter("VNC", p, p, port)
				mapMutex.Lock()
				res[p] = p
				mapMutex.Unlock()
				prt.PrintInfo(fmt.Sprintf("VNC Server of %s", p))
			}
			wg.Done()
		}(t)
	}
	wg.Wait()
	return res
}

func VerifyVNC(host string, port int) bool {
	conn, err := proxyconn.GetConnection(host, port)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var protocolVersion [12]byte
	// 7.1.1, read the ProtocolVersion message sent by the server.
	if _, err := io.ReadFull(conn, protocolVersion[:]); err != nil {
		return false
	}

	if len(protocolVersion) < 12 {
		// protocol version should be 12 bytes
		// eg: RFB 003.008
		return false
	}

	var major, minor uint
	l, err := fmt.Sscanf(string(protocolVersion[:]), "RFB %d.%d\n", &major, &minor)
	if l != 2 || err != nil {
		return false
	}
	return major == 3 && (minor == 3 || minor == 7 || minor == 8)
}

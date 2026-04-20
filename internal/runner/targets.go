package runner

import (
	"bufio"
	"net"
	"os"

	"github.com/mandiant/gopacket/pkg/session"
)

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func isFile(s string) bool {
	_, err := os.Stat(s)
	return err == nil
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func extract(list []string, recurse bool) []session.Target {
	var res []session.Target
	for _, l := range list {
		if isCIDR(l) {
			ip, ipnet, _ := net.ParseCIDR(l)
			var ips []string
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				ips = append(ips, ip.String())
			}
			for _, ip := range ips[1 : len(ips)-1] {
				res = append(res, session.Target{Host: ip})
			}
		} else if isFile(l) && recurse {
			o, _ := readLines(l)
			res = append(res, extract(o, false)...)
		} else {
			res = append(res, session.Target{Host: l})
		}
	}
	return res
}

func ExtractTargets(list []string) []session.Target {
	return extract(list, true)
}

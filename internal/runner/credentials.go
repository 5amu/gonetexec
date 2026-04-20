package runner

import (
	"github.com/mandiant/gopacket/pkg/session"
)

func NewCredentialsClusterBomb(users []string, passwords []string) (out []session.Credentials) {
	if len(passwords) == 0 {
		passwords = append(passwords, "")
	}
	for _, u := range users {
		for _, p := range passwords {
			out = append(out, session.Credentials{Username: u, Password: p})
		}
	}
	return
}

func NewCredentialsPitchFork(users []string, passwords []string) (out []session.Credentials) {
	for i := 0; i < len(users) && i < len(passwords); i++ {
		out = append(out, session.Credentials{Username: users[i], Password: passwords[i]})
	}
	return
}

func NewCredentialsNTLM(users []string, hash string) (out []session.Credentials) {
	for _, u := range users {
		out = append(out, session.Credentials{Username: u, Hash: hash})
	}
	return
}

type Strategy int

const (
	Clusterbomb Strategy = iota
	Pitchfork
)

func NewCredentialsDispacher(users, passwords, ntlm string, strategy Strategy) []session.Credentials {
	if ntlm != "" {
		return NewCredentialsNTLM(ExtractLinesFromFileOrString(users), ntlm)
	}
	if strategy == Pitchfork {
		return NewCredentialsPitchFork(ExtractLinesFromFileOrString(users), ExtractLinesFromFileOrString(passwords))
	}
	return NewCredentialsClusterBomb(ExtractLinesFromFileOrString(users), ExtractLinesFromFileOrString(passwords))
}

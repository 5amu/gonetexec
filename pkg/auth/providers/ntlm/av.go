package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/5amu/gonetexec/pkg/encoder"
)

type AvID uint16

const (
	AvIDMsvAvEOL AvID = iota
	AvIDMsvAvNbComputerName
	AvIDMsvAvNbDomainName
	AvIDMsvAvDNSComputerName
	AvIDMsvAvDNSDomainName
	AvIDMsvAvDNSTreeName
	AvIDMsvAvFlags
	AvIDMsvAvTimestamp
	AvIDMsvAvSingleHost
	AvIDMsvAvTargetName
	AvIDMsvChannelBindings
)

type TargetInformation struct {
	NbComputerName  string
	NbDomainName    string
	DNSComputerName string
	DNSDomainName   string
	DNSTreeName     string
	Flags           uint32
	Timestamp       uint64
	SingleHost      SingleHostData
	TargetName      string
	ChBindings      ChannelBindings

	// Internal
	size int
	raw  []byte
}

func ParseAvPairs(b []byte) (*TargetInformation, error) {
	//        AvPair
	//   0-2: AvId
	//   2-4: AvLen
	//    4-: Value
	if len(b) < 4 {
		return nil, fmt.Errorf("no av pair to parse")
	}

	var info TargetInformation
	for i := 0; i < len(b); {
		// Read AvID
		id := AvID(binary.LittleEndian.Uint16(b[i : i+2]))

		// If EOL return
		if id == AvIDMsvAvEOL {
			// Checking if the standard is followed as some fields MUST be
			// present in the AV pairs
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
			if info.NbComputerName == "" || info.NbDomainName == "" {
				return &info, fmt.Errorf("target info received is corrupted, this should not happen")
			}
			info.size = len(b)
			info.raw = b
			return &info, nil
		}

		// Read value size and check that it is not OOB
		sz := binary.LittleEndian.Uint16(b[i+2 : i+4])
		if len(b) < i+4+int(sz) {
			return nil, fmt.Errorf("corrupted data - refusing to go out of bounds")
		}

		if err := info.Set(id, b[i+4:i+4+int(sz)]); err != nil {
			return nil, err
		}

		i = i + 4 + int(sz)
	}
	return nil, fmt.Errorf("never reached AvId == AvIDMsvAvEOL")
}

func (t TargetInformation) Set(k AvID, v []byte) error {
	switch k {
	case AvIDMsvAvNbComputerName:
		t.NbComputerName = encoder.UnicodeToString(v)
	case AvIDMsvAvNbDomainName:
		t.NbDomainName = encoder.UnicodeToString(v)
	case AvIDMsvAvDNSComputerName:
		t.DNSComputerName = encoder.UnicodeToString(v)
	case AvIDMsvAvDNSDomainName:
		t.DNSDomainName = encoder.UnicodeToString(v)
	case AvIDMsvAvDNSTreeName:
		t.DNSTreeName = encoder.UnicodeToString(v)
	case AvIDMsvAvFlags:
		t.Flags = binary.LittleEndian.Uint32(v)
	case AvIDMsvAvTimestamp:
		t.Timestamp = binary.LittleEndian.Uint64(v)
	case AvIDMsvAvSingleHost:
		return encoder.Unmarshal(v, &t.SingleHost)
	case AvIDMsvAvTargetName:
		t.TargetName = encoder.UnicodeToString(v)
	case AvIDMsvChannelBindings:
		return encoder.Unmarshal(v, &t.ChBindings)
	}
	return nil
}

func (t TargetInformation) Size() int {
	return t.size
}

func (t TargetInformation) Raw(spn []byte) []byte {
	// remove EOL
	t.raw = t.raw[:len(t.raw)-4]

	// check if flags are defined
	if t.Flags == 0 {
		//        AvPair
		//   0-2: AvId
		//   2-4: AvLen
		//    4-: Value
		// define flags and append them to the raw bytes
		flagsAv := make([]byte, 8)
		binary.LittleEndian.PutUint32(flagsAv, uint32(0x02))
		t.raw = append(t.raw, flagsAv...)
	}

	// provide SPN if defined
	if len(spn) != 0 {
		targetName := make([]byte, 4+len(spn))
		binary.LittleEndian.PutUint16(targetName[0:2], uint16(AvIDMsvAvTargetName))
		binary.LittleEndian.PutUint16(targetName[2:4], uint16(len(spn)))
		_ = copy(targetName[4:], targetName)
	}

	// reinsert EOL
	eolAv := make([]byte, 4)
	binary.LittleEndian.PutUint16(eolAv[0:2], uint16(AvIDMsvAvEOL))
	binary.LittleEndian.PutUint16(eolAv[2:4], 0)
	t.raw = append(t.raw, eolAv...)
	return t.raw
}

type AvPairs map[AvID][]byte

func NewAvPairs(b []byte) (AvPairs, error) {
	var m AvPairs = make(map[AvID][]byte)
	for i := 0; i < len(b); {
		if len(b[i:]) < 4 {
			return nil, fmt.Errorf("corrupted data - refusing to go out of bounds")
		}

		// Read AvID
		id := AvID(binary.LittleEndian.Uint16(b[i : i+2]))

		// If EOL return
		if id == AvIDMsvAvEOL {
			// Checking if the standard is followed as some fields MUST be
			// present in the AV pairs
			// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
			_, ok1 := m[AvIDMsvAvNbComputerName]
			_, ok2 := m[AvIDMsvAvNbDomainName]
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("target info received is corrupted, this should not happen")
			}
			return m, nil
		}

		// Read value size and check that it is not OOB
		sz := binary.LittleEndian.Uint16(b[i+2 : i+4])
		if len(b) < i+4+int(sz) {
			return nil, fmt.Errorf("corrupted data - refusing to go out of bounds")
		}
		next := i + 4 + int(sz)
		m[id] = b[i+4 : next]
		i = next
	}
	return nil, fmt.Errorf("never reached AvId == AvIDMsvAvEOL")
}

func (p AvPairs) Bytes(spn []byte) []byte {
	// check if flags are defined
	if _, ok := p[AvIDMsvAvFlags]; !ok {
		//        AvPair
		//   0-2: AvId
		//   2-4: AvLen
		//    4-: Value
		// define flags and append them to the raw bytes
		flagsAv := make([]byte, 8)
		binary.LittleEndian.PutUint32(flagsAv, uint32(0x02))
		p[AvIDMsvAvFlags] = flagsAv
	}

	// provide SPN if defined
	if len(spn) != 0 {
		targetName := make([]byte, 4+len(spn))
		_ = copy(targetName[4:], targetName)
		p[AvIDMsvAvTargetName] = targetName
	}

	var buffer bytes.Buffer
	for k, v := range p {
		avid := make([]byte, 2)
		binary.LittleEndian.PutUint16(avid, uint16(k))
		alen := make([]byte, 2)
		binary.LittleEndian.PutUint16(alen, uint16(len(v)))

		buffer.Write(avid)
		buffer.Write(alen)
		buffer.Write(v)
	}

	buffer.Write([]byte{
		0, 0, // AvIDMsvAvEOL = 0
		0, 0, // AvLen
	})
	return buffer.Bytes()
}

func (p AvPairs) Get(id AvID) interface{} {
	if _, ok := p[id]; !ok {
		return nil
	}
	switch id {
	case AvIDMsvAvNbComputerName, AvIDMsvAvNbDomainName, AvIDMsvAvDNSComputerName,
		AvIDMsvAvDNSDomainName, AvIDMsvAvDNSTreeName, AvIDMsvAvTargetName:
		return encoder.UnicodeToString(p[id])
	case AvIDMsvAvFlags:
		return binary.LittleEndian.Uint32(p[id])
	case AvIDMsvAvTimestamp:
		return binary.LittleEndian.Uint64(p[id])
	case AvIDMsvAvSingleHost:
		var sh SingleHostData
		if err := encoder.Unmarshal(p[id], &sh); err != nil {
			return nil
		}
		return sh
	case AvIDMsvChannelBindings:
		var cb ChannelBindings
		if err := encoder.Unmarshal(p[id], &cb); err != nil {
			return nil
		}
		return cb
	}
	return nil
}

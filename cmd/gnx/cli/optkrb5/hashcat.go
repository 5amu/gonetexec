package optkrb5

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jcmturner/gokrb5/v8/messages"
)

func TGSToHashcat(tgs messages.Ticket, username string) string {
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tgs.EncPart.EType,
		username,
		tgs.Realm,
		strings.Join(tgs.SName.NameString[:], "/"),
		hex.EncodeToString(tgs.EncPart.Cipher[:16]),
		hex.EncodeToString(tgs.EncPart.Cipher[16:]),
	)
}

func ASREPToHashcat(asrep messages.ASRep) string {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		asrep.CName.PrincipalNameString(),
		asrep.CRealm,
		hex.EncodeToString(asrep.EncPart.Cipher[:16]),
		hex.EncodeToString(asrep.EncPart.Cipher[16:]),
	)
}

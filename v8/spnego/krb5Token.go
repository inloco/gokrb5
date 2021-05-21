package spnego

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
	settings *service.Settings
	context  context.Context
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	var err error
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		return []byte{}, errors.New("marshal of AP_REP GSSAPI MechToken not supported by gokrb5")
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by gokrb5")
	}
	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %v", err)
	}
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s", oid.String(), gssapi.OIDKRB5.OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = a
	}
	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		ok, creds, err := service.VerifyAPREQ(&m.APReq, m.settings)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		if !ok {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveCredential, Message: "KRB5_AP_REQ token not valid"}
		}
		m.context = context.Background()
		m.context = context.WithValue(m.context, ctxCredentials, creds)
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		// Client side
		// TODO how to verify the AP_REP - not yet implemented
		return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "verifying an AP_REP is not currently supported by gokrb5"}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}
		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}
	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ {
		return true
	}
	return false
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP {
		return true
	}
	return false
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR {
		return true
	}
	return false
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token
	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := krb5TokenAuthenticator(cl, sessionKey, GSSAPIFlags)
	if err != nil {
		return m, err
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range APOptions {
		types.SetFlag(&APReq.APOptions, o)
	}
	m.APReq = APReq
	return m, nil
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken
func krb5TokenAuthenticator(cl *client.Client, sessionKey types.EncryptionKey, flags []int) (types.Authenticator, error) {
	creds := cl.Credentials

	//RFC 4121 Section 4.1.1
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	checksum, err := newAuthenticatorChksum(cl, sessionKey, flags)
	if err != nil {
		return auth, err
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  checksum,
	}

	return auth, nil
}

// Create new authenticator checksum for kerberos MechToken
func newAuthenticatorChksum(cl *client.Client, sessionKey types.EncryptionKey, flags []int) ([]byte, error) {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		if i == gssapi.ContextFlagDeleg {
			deleg, err := credDeleg(cl, sessionKey)
			if err != nil {
				return nil, err
			}

			size := []byte{0, 0}
			binary.LittleEndian.PutUint16(size, uint16(len(deleg)))

			a = append(a, 0x01, 0x00, size[0], size[1])
			a = append(a, deleg...)
		}

		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}

	return a, nil
}

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets []asn1.RawValue     `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

type marshalEncKrbCredPart struct {
	TicketInfo []marshalKrbCredInfo `asn1:"explicit,tag:0"`
	Nouce      int                  `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time            `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int                  `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress    `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress    `asn1:"optional,explicit,tag:5"`
}

type marshalKrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"generalstring,optional,explicit,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

func credDeleg(cl *client.Client, sessionKey types.EncryptionKey) ([]byte, error) {
	realm := cl.Credentials.Domain()

	spn := types.PrincipalName{
		NameType: nametype.KRB_NT_SRV_INST,
		NameString: []string{
			"krbtgt",
			realm,
		},
	}

	tgt, skey, err := cl.GetServiceTicket(spn.PrincipalNameString())
	if err != nil {
		return nil, err
	}

	tgsReq, err := messages.NewTGSReq(cl.Credentials.CName(), realm, cl.Config, tgt, skey, spn, false)
	if err != nil {
		return nil, err
	}

	_, tgsRep, err := cl.TGSExchange(tgsReq, realm, messages.Ticket{}, skey, 0)
	if err != nil {
		return nil, err
	}

	decPart := marshalEncKrbCredPart{
		TicketInfo: []marshalKrbCredInfo{
			marshalKrbCredInfo{
				Key:       sessionKey,
				PRealm:    tgsRep.CRealm,
				PName:     tgsRep.CName,
				Flags:     tgsRep.DecryptedEncPart.Flags,
				AuthTime:  tgsRep.DecryptedEncPart.AuthTime,
				StartTime: tgsRep.DecryptedEncPart.StartTime,
				EndTime:   tgsRep.DecryptedEncPart.EndTime,
				RenewTill: tgsRep.DecryptedEncPart.RenewTill,
				SRealm:    tgsRep.DecryptedEncPart.SRealm,
				SName:     tgsRep.DecryptedEncPart.SName,
				CAddr:     tgsRep.DecryptedEncPart.CAddr,
			},
		},
		Timestamp: time.Now(),
	}

	decPartBytes, err := asn1.Marshal(decPart)
	if err != nil {
		return nil, err
	}

	encPart, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(decPartBytes, asnAppTag.EncKrbCredPart), sessionKey, keyusage.KRB_CRED_ENCPART, 0)
	if err != nil {
		return nil, err
	}

	ticketBytes, err := asn1.Marshal(tgsRep.Ticket)
	if err != nil {
		return nil, err
	}

	cred := marshalKRBCred{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_CRED,
		Tickets: []asn1.RawValue{
			asn1.RawValue{
				Class:      asn1.ClassApplication,
				Tag:        asnAppTag.Ticket,
				IsCompound: true,
				Bytes:      ticketBytes,
			},
		},
		EncPart: encPart,
	}

	credBytes, err := asn1.Marshal(cred)
	if err != nil {
		return nil, err
	}

	return asn1tools.AddASNAppTag(credBytes, asnAppTag.KRBCred), nil
}

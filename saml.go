package saml2

import (
	"sync"

	dsig "github.com/komly/goxmldsig"
)

const issueInstantFormat = "2006-01-02T15:04:05Z"

type SAMLServiceProvider struct {
	IdentityProviderSSOURL      string
	IdentityProviderIssuer      string
	AssertionConsumerServiceURL string
	SignAuthnRequests           bool
	SignAuthnRequestsAlgorithm  string
	AudienceURI                 string
	IDPCertificateStore         dsig.X509CertificateStore
	SPKeyStore                  dsig.X509KeyStore
	NameIdFormat                string
	SkipSignatureValidation     bool
	Clock                       *dsig.Clock
	signingContextMu            sync.RWMutex
	signingContext              *dsig.SigningContext
}

func (sp *SAMLServiceProvider) SigningContext() *dsig.SigningContext {
	sp.signingContextMu.RLock()
	signingContext := sp.signingContext
	sp.signingContextMu.RUnlock()

	if signingContext != nil {
		return signingContext
	}

	sp.signingContextMu.Lock()
	defer sp.signingContextMu.Unlock()

	sp.signingContext = dsig.NewDefaultSigningContext(sp.SPKeyStore)
	sp.signingContext.SetSignatureMethod(sp.SignAuthnRequestsAlgorithm)
	return sp.signingContext
}

type ProxyRestriction struct {
	Count    int
	Audience []string
}

type WarningInfo struct {
	OneTimeUse       bool
	ProxyRestriction *ProxyRestriction
	NotInAudience    bool
	InvalidTime      bool
}

type AssertionInfo struct {
	NameID      string
	Values      Values
	WarningInfo *WarningInfo
}

func childPath(space, tag string) string {
	if space == "" {
		return "./" + tag
	}
	return "./" + space + ":" + tag
}

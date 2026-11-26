package sources

import "strings"

// Keys holds optional API keys. IPData and CFRadar require a key; other empty
// values use the free anonymous tiers.
type Keys struct {
	IPInfo, IPAPIIs, ProxyCheck, IP2Location, GreyNoise, IPData, CFRadar string
}

// All returns every provider in display order.
func All(k Keys) []*Provider {
	providers := []*Provider{
		ipAPI(), ipWho(), ipSB(), ipapiIs(k.IPAPIIs), ipinfo(k.IPInfo), ipapiCo(), ip2locationIO(k.IP2Location),
		ipQuery(), blackbox(),
		proxycheck(k.ProxyCheck), ipyou(), greynoise(k.GreyNoise), stopForumSpam(), sansDShield(), alienVaultOTX(), torOnionoo(),
		internetDB(), hackertarget(),
		zxinc(), baidu(), rdap(), rdapASN(), asnSpace(), ripeRouting(), ripeRIR(), ripeRPKI(), peeringDB(),
	}
	if k.IPData != "" {
		providers = append(providers, ipdata(k.IPData))
	}
	if strings.TrimSpace(k.CFRadar) != "" {
		providers = append(providers, cloudflareRadar(k.CFRadar))
	}
	return providers
}

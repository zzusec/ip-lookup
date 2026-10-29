package sources

// Keys holds optional API keys; empty values use the free anonymous tiers.
type Keys struct {
	IPInfo, IPAPIIs, ProxyCheck, IP2Location, GreyNoise string
}

// All returns every provider in display order.
func All(k Keys) []*Provider {
	return []*Provider{
		ipAPI(), ipWho(), ipSB(), ipapiIs(k.IPAPIIs), ipinfo(k.IPInfo), ipapiCo(), ip2locationIO(k.IP2Location),
		proxycheck(k.ProxyCheck), ipyou(), greynoise(k.GreyNoise), internetDB(), hackertarget(),
		zxinc(), baidu(), rdap(), ripeRouting(), ripeRIR(), ripeRPKI(), peeringDB(),
	}
}

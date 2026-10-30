package sources

import (
	"testing"

	"github.com/zzusec/ip-lookup/internal/model"
)

func TestZxincGeo(t *testing.T) {
	cases := []struct {
		place, local string
		want         model.GeoSource
	}{
		{"美国–加利福尼亚州–洛杉矶–洛杉矶", "DMIT", model.GeoSource{Country: "美国", CountryCode: "US", Region: "加利福尼亚州", City: "洛杉矶", ISP: "DMIT"}},
		{"美国–加利福尼亚州–圣克拉拉–山景城", "谷歌公司DNS服务器", model.GeoSource{Country: "美国", CountryCode: "US", Region: "加利福尼亚州", City: "山景城", ISP: "谷歌公司DNS服务器"}},
		{"荷兰–北荷兰省–阿姆斯特丹", "Tor出口节点", model.GeoSource{Country: "荷兰", CountryCode: "NL", Region: "北荷兰省", City: "阿姆斯特丹", ISP: "Tor出口节点"}},
		{"马来西亚", "CZ88.NET", model.GeoSource{Country: "马来西亚", CountryCode: "MY"}},
		{"中国–广东–广州", "移动", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "广东", City: "广州", ISP: "移动"}},
		{"中国–广东–深圳–南山", "电信", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "广东", City: "深圳", ISP: "电信"}},
		{"中国–北京–北京", "联通/DNS服务器", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "北京", City: "北京", ISP: "联通/DNS服务器"}},
		{"中国", "电信/DNS派公共DNS", model.GeoSource{Country: "中国", CountryCode: "CN", ISP: "电信/DNS派公共DNS"}},
		{"中国–香港", "电讯盈科有限公司", model.GeoSource{Country: "香港", CountryCode: "HK", ISP: "电讯盈科有限公司"}},
		{"中国–台湾", "中华电信(HiNet)数据中心DNS服务器", model.GeoSource{Country: "台湾", CountryCode: "TW", ISP: "中华电信(HiNet)数据中心DNS服务器"}},
		{"中国–澳门", "澳门电讯", model.GeoSource{Country: "澳门", CountryCode: "MO", ISP: "澳门电讯"}},
		{"", "", model.GeoSource{}},
	}
	for _, c := range cases {
		got := zxincGeo(c.place+" "+c.local, c.place, c.local)
		got.Text = ""
		c.want.Source = "纯真 (zxinc)"
		if got != c.want {
			t.Errorf("zxincGeo(%q, %q) = %+v, want %+v", c.place, c.local, got, c.want)
		}
	}
	g := zxincGeo("美国–加利福尼亚州–洛杉矶–洛杉矶 DMIT", "美国–加利福尼亚州–洛杉矶–洛杉矶", "DMIT")
	if want := "美国 加利福尼亚州 洛杉矶 洛杉矶 DMIT"; g.Text != want {
		t.Errorf("text = %q, want %q", g.Text, want)
	}
}

func TestBaiduGeo(t *testing.T) {
	cases := []struct {
		loc, region, city string
		want              model.GeoSource
	}{
		{"美国加利福尼亚", "加州", "洛杉矶", model.GeoSource{Country: "美国", CountryCode: "US", Region: "加利福尼亚"}},
		{"美国加利福尼亚洛杉矶", "加州", "洛杉矶", model.GeoSource{Country: "美国", CountryCode: "US", Region: "加利福尼亚", City: "洛杉矶"}},
		{"美国纽约布鲁克林", "纽约", "纽约", model.GeoSource{Country: "美国", CountryCode: "US", Region: "纽约", City: "布鲁克林"}},
		{"美国", "", "", model.GeoSource{Country: "美国", CountryCode: "US"}},
		{"荷兰阿姆斯特丹", "北荷兰省", "阿姆斯特丹", model.GeoSource{Country: "荷兰", CountryCode: "NL", City: "阿姆斯特丹"}},
		{"加拿大魁北克", "魁北克省", "蒙特利尔", model.GeoSource{Country: "加拿大", CountryCode: "CA", Region: "魁北克"}},
		{"印度尼西亚雅加达", "", "", model.GeoSource{Country: "印度尼西亚", CountryCode: "ID", Region: "雅加达"}},
		{"广东省广州市 移动", "", "", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "广东省", City: "广州市", ISP: "移动"}},
		{"北京市北京市 联通", "", "", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "北京市", City: "北京市", ISP: "联通"}},
		{"广西壮族自治区南宁市 电信", "", "", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "广西壮族自治区", City: "南宁市", ISP: "电信"}},
		{"浙江省杭州市 阿里云", "", "", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "浙江省", City: "杭州市", ISP: "阿里云"}},
		{"中国北京", "", "", model.GeoSource{Country: "中国", CountryCode: "CN", Region: "北京"}},
		{"香港特别行政区", "", "", model.GeoSource{Country: "香港", CountryCode: "HK"}},
		{"台湾省", "", "", model.GeoSource{Country: "台湾", CountryCode: "TW"}},
		{"保留地址 本地", "", "", model.GeoSource{}},
	}
	for _, c := range cases {
		got := baiduGeo(c.loc, c.region, c.city)
		c.want.Source, c.want.Text = "百度 IP", c.loc
		if got != c.want {
			t.Errorf("baiduGeo(%q, %q, %q) = %+v, want %+v", c.loc, c.region, c.city, got, c.want)
		}
	}
}

func TestCountryZH(t *testing.T) {
	for n, c := range map[string]string{"美国": "US", "英国": "GB", "俄罗斯": "RU", "韩国": "KR", "阿联酋": "AE", "印度": "IN", "印度尼西亚": "ID"} {
		if countryZH[n] != c {
			t.Errorf("countryZH[%q] = %q, want %q", n, countryZH[n], c)
		}
	}
	// 百度 writes Chinese places without 中国, so no country may start them.
	for _, p := range []string{"中国", "北京", "天津", "河北", "山西", "内蒙古", "辽宁", "吉林", "黑龙江", "上海",
		"江苏", "浙江", "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南", "广东", "广西", "海南", "重庆",
		"四川", "贵州", "云南", "西藏", "陕西", "甘肃", "青海", "宁夏", "新疆", "香港", "澳门", "台湾"} {
		if n, c := zhCountry(p + "省"); c != "" {
			t.Errorf("%s reads as country %s (%s)", p, n, c)
		}
	}
}

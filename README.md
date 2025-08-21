# 🌐 OpenRay

*A community-driven attempt to keep the internet open and affordable.*

---

## ✨ Story

The story began when free proxies in **Iran** kept disconnecting almost every hour, forcing people to pay for premium services.  
Yet, paid proxies often charge unreasonable prices—a heavy burden given today’s economy.

So I rolled up my sleeves.  
I started tracking down repositories and websites that collect free proxies from across the internet. Then, I built a pipeline to **fetch, clean, and test** them automatically, filtering out the dead or low-quality ones.  

What remains is a curated list of **working, high-quality proxies** that anyone can use—completely free.

This is an **open-source project**, made for the community, to help those who simply need reliable access to the internet.

---


## 🔗 Full Proxy Collection

👉 [**Download All Proxies (Latest Build)**](output/all_valid_proxies.txt)

---

## 📑 Proxy List by Type

| | | | |
|---|---|---|---|
| 🔵 [**Vmess**](output/kind/vmess.txt) | 🟢 [**Vless**](output/kind/vless.txt) | 🔒 [**Trojan**](output/kind/trojan.txt) | ⚡ [**Shadowsocks (SS)**](output/kind/ss.txt) |
| 🔑 [**ShadowsocksR (SSR)**](output/kind/ssr.txt) | 🌐 [**Hysteria / Hy2**](output/kind/hysteria.txt) | 🚀 [**TUIC**](output/kind/tuic.txt) | 🧃 [**Juicity**](output/kind/juicity.txt) |

---

## 🌍 Proxy List by Country

| | | | |
|---|---|---|---|
| 🇺🇸 [**United States**](output/countery/US.txt) | 🇩🇪 [**Germany**](output/countery/DE.txt) | 🇬🇧 [**United Kingdom**](output/countery/GB.txt) | 🇫🇷 [**France**](output/countery/FR.txt) |
| 🇨🇦 [**Canada**](output/countery/CA.txt) | 🇯🇵 [**Japan**](output/countery/JP.txt) | 🇸🇬 [**Singapore**](output/countery/SG.txt) | 🇷🇺 [**Russia**](output/countery/RU.txt) |
| 🇳🇱 [**Netherlands**](output/countery/NL.txt) | 🇨🇭 [**Switzerland**](output/countery/CH.txt) | 🇸🇪 [**Sweden**](output/countery/SE.txt) | 🇦🇺 [**Australia**](output/countery/AU.txt) |
| 🇮🇷 [**Iran**](output/countery/IR.txt) | 🇨🇳 [**China**](output/countery/CN.txt) | 🇭🇰 [**Hong Kong**](output/countery/HK.txt) | 🇰🇷 [**South Korea**](output/countery/KR.txt) |
| 🇮🇹 [**Italy**](output/countery/IT.txt) | 🇪🇸 [**Spain**](output/countery/ES.txt) | 🇧🇷 [**Brazil**](output/countery/BR.txt) | 🇲🇽 [**Mexico**](output/countery/MX.txt) |
| 🇮🇳 [**India**](output/countery/IN.txt) | 🇹🇷 [**Turkey**](output/countery/TR.txt) | 🇺🇦 [**Ukraine**](output/countery/UA.txt) | 🇵🇱 [**Poland**](output/countery/PL.txt) |
| 🇨🇿 [**Czech Republic**](output/countery/CZ.txt) | 🇭🇷 [**Croatia**](output/countery/HR.txt) | 🇮🇪 [**Ireland**](output/countery/IE.txt) | 🌐 [**Other Countries**](output/countery/XX.txt) |


## ⚡ Features

- ✅ Fetch from multiple source URLs (raw pages or base64 subscriptions)  
- ✅ Extract supported schemes: `vmess`, `vless`, `trojan`, `ss`, `ssr`, `hysteria/hysteria2/hy2`, `tuic`, `juicity`  
- ✅ Perform parallel reachability checks (ICMP ping + TCP port connect)  
- ✅ Optional Stage 2: TLS/protocol probing after TCP connect  
- ✅ Optional Stage 3: Validation via a local Xray/V2Ray core (auto-detected)  
- ✅ Persistent tracking of tested items with host stability streaks  
- ✅ Outputs grouped by scheme and by country, with readable remarks including flags + sequence numbers  
- ✅ Optional export of ready-to-use V2Ray/Xray JSON configs  

---

## 🤝 Contributing

- 🔍 **Know a proxy source not in `sources.txt`?** → Open an issue or PR to suggest adding it!  
- ⭐ **Found this repo useful?** → Don’t forget to give it a **star** — it helps others discover it!  
- 💡 **Ideas for improvement?** → Share feedback in issues/discussions.  

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**.  
You are solely responsible for how you use the provided links.

---

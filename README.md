# 🌐 OpenRay

<div align="center">

**A community-driven attempt to keep the internet open and affordable**

[![Stars](https://img.shields.io/github/stars/sakha1370/OpenRay?style=for-the-badge&logo=github&color=gold)](https://github.com/sakha1370/OpenRay/stargazers)
[![Forks](https://img.shields.io/github/forks/sakha1370/OpenRay?style=for-the-badge&logo=github&color=blue)](https://github.com/sakha1370/OpenRay/network/members)
[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg?style=for-the-badge&logo=python)](https://python.org)
[![Contributors](https://img.shields.io/github/contributors/sakha1370/OpenRay?style=for-the-badge&logo=people&color=green)](https://github.com/sakha1370/OpenRay/graphs/contributors)

*Free, tested, and reliable proxy lists for everyone*

[🚀 Quick Start](#-quick-start) • [📋 Proxy Lists](#-proxy-collections) • [🤝 Contributing](#-contributing) • [⭐ Star Growth](#-github-star-growth)

</div>

---

## Collector runtime

The collector uses Python 3.13+, transactional SQLite, bounded asynchronous queues and pinned Xray, sing-box and mihomo cores. Subscription paths and URLs remain available. New candidates require an end-to-end successful check; infrastructure failures preserve existing connection health.

```bash
python -m pip install -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
python tools/install_cores.py
python -m openray migrate
python -m openray run --report .state/latest-run.json
```

The run stages an immutable snapshot. Installation and publishing are separate commands with client validation gates. Read the [implementation evidence](docs/implementation.md), [operations and recovery guide](docs/operations.md), [compatibility contract](docs/compatibility.json), and [protocol matrix](docs/protocols.md) before a production cutover. The 24-hour endurance and representative week of network canaries remain deployment acceptance gates.

## ✨ Our Story

The journey began when free proxies in **Iran** kept disconnecting almost hourly, forcing users to pay exorbitant prices for premium services. Frustrated by this cycle, I built an automated pipeline that:

- **🔍 Fetches** proxies from trusted sources across the internet
- **⚡ Tests** each proxy for reliability and speed  
- **🧹 Filters** out dead or low-quality connections
- **📦 Curates** only the best working proxies

The result? **Free, high-quality proxy lists** that anyone can use, completely open-source and community-driven.

> *"Breaking the cycle of expensive internet access, one proxy at a time."*

---

## 🚀 Quick Start

### For Immediate Use

**🌍 Global Users:**
```bash
# Download all tested proxies
curl -s https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt
```

**🇮🇷 Iran Users (Optimized):**
```bash
# get just the top 100 most reliable
curl -s https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt
```

### 📱 Popular Clients

<div align="center">
<table>
<tr>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/Desktop-Clash_Verge-purple?style=flat-square&logo=linux" alt="Clash Verge"><br>
<strong>Clash Verge Rev</strong><br>
<a href="https://github.com/clash-verge-rev/clash-verge-rev/releases/latest">📥 Download</a><br>
<em>Windows/macOS/Linux</em>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/Android-v2rayNG-green?style=flat-square&logo=android" alt="v2rayNG"><br>
<strong>v2rayNG</strong><br>
<a href="https://github.com/2dust/v2rayNG/releases/latest">📥 Download</a><br>
<em>Android</em>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/Cross_Platform-v2rayN-blue?style=flat-square&logo=github" alt="v2rayN"><br>
<strong>v2rayN</strong><br>
<a href="https://github.com/2dust/v2rayN/releases/latest">📥 Download</a><br>
<em>Multi-platform GUI</em>
</td>
<td align="center" width="25%">
<img src="https://img.shields.io/badge/Universal-Hiddify-orange?style=flat-square&logo=shield" alt="Hiddify"><br>
<strong>Hiddify App</strong><br>
<a href="https://github.com/hiddify/hiddify-app/releases/latest">📥 Download</a><br>
<em>All Platforms</em>
</td>
</tr>
</table>
</div>

---


## 📋 Proxy Collections

### 🌍 Global Collection

<div align="center">

#### 📦 Complete Collection
[![Download All](https://img.shields.io/badge/Download-All_Proxies-2ea043?style=for-the-badge&logo=download&logoColor=white)](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt)

#### ⚙️ Ready-to-Use Configs
<table>
<tr>
<td align="center">
<strong>📱 Clash Format</strong><br>
<a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/converted/all_valid_proxies_clash_config.yaml">
<img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=for-the-badge&logo=yaml" alt="Clash Config">
</a>
</td>
<td align="center">
<strong>🚀 Singbox Format</strong><br>
<a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/converted/all_valid_proxies_singbox_config.json">
<img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=for-the-badge&logo=json" alt="Singbox Config">
</a>
</td>
</tr>
</table>

</div>

#### 🔧 By Protocol Type

<div align="center">
<table>
<tr>
<td align="center"><strong>🔵 VMess</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vmess.txt">Download</a><br><em>Versatile V2Ray</em></td>
<td align="center"><strong>🟢 VLess</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/vless.txt">Download</a><br><em>Lightweight V2Ray</em></td>
<td align="center"><strong>🔒 Trojan</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/trojan.txt">Download</a><br><em>TLS-based protocol</em></td>
<td align="center"><strong>⚡ Shadowsocks</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/ss.txt">Download</a><br><em>Fast SOCKS5</em></td>
</tr>
<tr>
<td align="center"><strong>🔑 ShadowsocksR</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/ssr.txt">Download</a><br><em>Extended SS</em></td>
<td align="center"><strong>🌐 Hysteria</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/hysteria.txt">Download</a><br><em>High-performance UDP</em></td>
<td align="center"><strong>🚀 TUIC</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/tuic.txt">Download</a><br><em>QUIC-based</em></td>
<td align="center"><strong>🧃 Juicity</strong><br><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/kind/juicity.txt">Download</a><br><em>Modern QUIC</em></td>
</tr>
</table>
</div>

#### 🌎 By Country/Region

<details>
<summary><strong>🌍 Popular Locations (Click to expand)</strong></summary>

<div align="center">
<table>
<tr>
<th>🌎 Americas</th>
<th>🌍 Europe</th>
<th>🌏 Asia Pacific</th>
<th>🕌 Middle East</th>
</tr>
<tr>
<td align="center">
🇺🇸 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/US.txt">United States</a><br>
🇨🇦 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/CA.txt">Canada</a><br>
🇧🇷 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/BR.txt">Brazil</a><br>
🇦🇺 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/AU.txt">Australia</a>
</td>
<td align="center">
🇩🇪 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/DE.txt">Germany</a><br>
🇬🇧 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/GB.txt">United Kingdom</a><br>
🇫🇷 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/FR.txt">France</a><br>
🇳🇱 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/NL.txt">Netherlands</a>
</td>
<td align="center">
🇯🇵 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/JP.txt">Japan</a><br>
🇸🇬 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/SG.txt">Singapore</a><br>
🇰🇷 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/KR.txt">South Korea</a><br>
🇭🇰 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/HK.txt">Hong Kong</a>
</td>
<td align="center">
🇮🇷 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/IR.txt">Iran</a><br>
🇹🇷 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/TR.txt">Turkey</a><br>
🇦🇪 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/AE.txt">UAE</a><br>
🇸🇦 <a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/SA.txt">Saudi Arabia</a>
</td>
</tr>
</table>

**More:** 🇷🇺 [Russia](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/RU.txt) • 🇨🇳 [China](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/CN.txt) • 🇮🇳 [India](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/IN.txt) • 🇮🇹 [Italy](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/IT.txt) • 🇪🇸 [Spain](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/ES.txt) • 🌐 [All Others](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/XX.txt)

</div>
</details>

---

### 🇮🇷 Iran-Optimized Collection

<div align="center">

#### 🏆 Top 100 Most Reliable
[![Top 100](https://img.shields.io/badge/Top_100-Most_Reliable-ff6b6b?style=for-the-badge&logo=star&logoColor=white)](https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/iran_top100_checked.txt)

#### 📊 Operator-Specific Rankings & Configurations
<div align="center">
<table>
<tr>
<th>Carrier</th>
<th>📋 Raw Proxies</th>
<th>📱 Clash Config</th>
<th>🚀 Singbox Config</th>
<th>Description</th>
</tr>
<tr>
<td align="center"><strong>📱 MCI</strong></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/mci_top100.txt">Download</a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/mci_top100_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash MCI"></a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/mci_top100_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox MCI"></a></td>
<td>Iran Cell (Hamrah-e-Aval) optimized proxies</td>
</tr>
<tr>
<td align="center"><strong>📶 Irancell</strong></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/irancell_top100.txt">Download</a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/irancell_top100_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash Irancell"></a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/irancell_top100_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox Irancell"></a></td>
<td>Irancell (MTN IranCell) optimized proxies</td>
</tr>
<tr>
<td align="center"><strong>🌐 TCI</strong></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/tci_top100.txt">Download</a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/tci_top100_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash TCI"></a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/tci_top100_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox TCI"></a></td>
<td>Telecommunication Company of Iran optimized proxies</td>
</tr>
<tr>
<td align="center"><strong>🌍 Others</strong></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/others_top100.txt">Download</a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/others_top100_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash Others"></a></td>
<td><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/others_top100_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox Others"></a></td>
<td>Other carriers and general Iran-optimized proxies</td>
</tr>
</table>
</div>

#### 🏆 General Iran-Optimized Configs
<div align="center">
<table>
<tr>
<th>Format</th>
<th>🏆 Top 100</th>
<th>📦 Full Collection</th>
</tr>
<tr>
<td align="center"><strong>📱 Clash</strong></td>
<td align="center"><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/iran_top100_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash Top 100"></a></td>
<td align="center"><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/iran_all_valid_proxies_clash_config.yaml"><img src="https://img.shields.io/badge/YAML-Config-ff6b6b?style=flat-square&logo=yaml" alt="Clash All"></a></td>
</tr>
<tr>
<td align="center"><strong>🚀 Singbox</strong></td>
<td align="center"><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/iran_top100_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox Top 100"></a></td>
<td align="center"><a href="https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output_iran/converted/iran_all_valid_proxies_singbox_config.json"><img src="https://img.shields.io/badge/JSON-Config-4ecdc4?style=flat-square&logo=json" alt="Singbox All"></a></td>
</tr>
</table>
</div>
</div>


---
## ✈️ Telegram Proxies Collection
<div align="center">
📦 Complete Telegram Collection

[![Download All](https://img.shields.io/badge/Download-All_Proxies-5865F2?style=for-the-badge&logo=telegram&logoColor=white)](https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt)
</div>

---

## ⚡ Features

<div align="center">
<table>
<tr>
<td align="center" width="25%">
<h4>🔍 Smart Discovery</h4>
<p>Multi-source fetching from raw pages and base64 subscriptions with 50+ countries coverage</p>
</td>
<td align="center" width="25%">
<h4>⚡ Lightning Testing</h4>
<p>Bounded asynchronous processing with authenticated, end-to-end protocol validation</p>
</td>
<td align="center" width="25%">
<h4>📊 Intelligent Organization</h4>
<p>Protocol categorization, geographic grouping, and stability tracking</p>
</td>
<td align="center" width="25%">
<h4>🎯 Iran Optimization</h4>
<p>Specialized filtering and top 100 reliability ranking for Iranian networks</p>
</td>
</tr>
</table>
</div>

### 🚀 **Core Capabilities**
- ✅ **Protocol-aware validation and exports**: see the [capability matrix](docs/protocols.md), including explicit unsupported outcomes
- ✅ **End-to-end validation**: supervised protocol cores, authenticated loopback probes, deadlines and target policies
- ✅ **Geographic Intelligence**: 50+ countries with flag indicators and regional optimization
- ✅ **Auto-Generated Configs**: Ready-to-use Clash and Singbox configurations
- ✅ **Stability Tracking**: Persistent monitoring with reliability streaks
- ✅ **Auto-Core Detection**: Automatic Xray/V2Ray core detection and integration
- ✅ **Operator-Specific Tracking**: Detailed Iran carrier analytics (MCI, Irancell, TCI, Others)

### 📊 **Data Structure & Analytics**
SQLite is authoritative for connection health and historical counters. This compatibility JSON is a materialized export, not a database checkpoint:

**Exported score structure:**
```json
{
  "vless://uuid@server:port": {
    "global": 17,
    "iran": {
      "total": 5,
      "operators": {
        "mci": 1,
        "irancell": 3,
        "tci": 1,
        "others": 0
      }
    }
  }
}
```

**Iran Carrier-Specific CLI Commands:**
```bash
# Track MCI (Iran Cell) optimized proxies
python3 -m src.main_for_iran --mci

# Track Irancell optimized proxies
python3 -m src.main_for_iran --irancell

# Track TCI (Telecom) optimized proxies
python3 -m src.main_for_iran --tci

# Default: Track "others" category
python3 -m src.main_for_iran
```

---

## 🤝 Contributing

<div align="center">

### 🌟 **Join Our Growing Community!**

[![Contributors](https://img.shields.io/github/contributors/sakha1370/OpenRay?style=for-the-badge&color=success)](https://github.com/sakha1370/OpenRay/graphs/contributors)
[![Issues](https://img.shields.io/github/issues/sakha1370/OpenRay?style=for-the-badge&color=yellow)](https://github.com/sakha1370/OpenRay/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/sakha1370/OpenRay?style=for-the-badge&color=blue)](https://github.com/sakha1370/OpenRay/pulls)

</div>

### 💡 **Ways to Help**

#### 🔍 **Add New Proxy Sources**
Found a reliable proxy source? Help expand our network!

```bash
# Add to these files:
sources.txt         # Global sources  
```

**Then:** [Open an issue](https://github.com/sakha1370/OpenRay/issues) or [submit a PR](https://github.com/sakha1370/OpenRay/pulls)!

#### 🐛 **Report & Fix Issues**
- 🐛 **Found a bug?** → [Create an issue](https://github.com/sakha1370/OpenRay/issues/new/choose)
- 💡 **Have an idea?** → [Start a discussion](https://github.com/sakha1370/OpenRay/discussions)
- 📚 **Need help?** → [Check discussions](https://github.com/sakha1370/OpenRay/discussions)

#### ⭐ **Show Your Support**
- ⭐ **Star this repo** to help others discover it
- 🔄 **Share** with friends and communities  
- 💻 **Contribute code** improvements and features
- 📝 **Improve documentation** and guides

#### 📝 **Code Standards**
- ✅ **Follow PEP 8** style guidelines
- ✅ **Add docstrings** to new functions
- ✅ **Test thoroughly** before submitting
- ✅ **Update docs** as needed

#### 🎯 **Proxy Source Guidelines**
<div align="center">
<table>
<tr>
<th>✅ Include</th>
<th>❌ Avoid</th>
</tr>
<tr>
<td>
• Reliable sources with consistent uptime<br>
• Legal and ethical proxy providers<br>
• Diverse protocols and locations<br>
• Well-maintained repositories
</td>
<td>
• Potentially malicious sources<br>
• Compromised or suspicious providers<br>
• Sources with frequent downtime<br>
• Illegal or questionable services
</td>
</tr>
</table>
</div>

---

## 📊 Project Statistics

<div align="center">
<table>
<tr>
<td align="center">
<strong>🌐 Global Reach</strong><br>
<img src="https://img.shields.io/badge/50+-Countries-blue?style=for-the-badge">
</td>
<td align="center">
<strong>🔄 Auto Updates</strong><br>
<img src="https://img.shields.io/badge/Every-Hour-green?style=for-the-badge">
</td>
<td align="center">
<strong>⚡ Protocols</strong><br>
<img src="https://img.shields.io/badge/8+-Types-orange?style=for-the-badge">
</td>
<td align="center">
<strong>✅ Success Rate</strong><br>
<a href="docs/implementation.md">Measured checks and remaining acceptance gates</a>
</td>
</tr>
</table>
</div>

---

<div align="center">

## ⚠️ **Important Disclaimer**

<table>
<tr>
<td align="center">
<strong>📚 Educational & Research Use Only</strong><br>
<em>This project is intended for educational and research purposes.</em><br>
<strong>You are solely responsible for how you use the provided connections.</strong><br>
<br>
<em>Please use responsibly and in accordance with your local laws.</em>
</td>
</tr>
</table>

---

<h3>🌟 Made with ❤️ for the Open Internet Community</h3>

<p><em>Keeping the internet accessible, one proxy at a time</em></p>

[![Star History Chart](https://api.star-history.com/svg?repos=sakha1370/OpenRay&type=Date)](https://star-history.com/#sakha1370/OpenRay&Date)

**[⭐ Star this project](https://github.com/sakha1370/OpenRay)** • **[🔄 Share with friends](https://github.com/sakha1370/OpenRay)** • **[🤝 Contribute](https://github.com/sakha1370/OpenRay#-contributing)**

[⬆️ Back to Top](#-openray)

</div>
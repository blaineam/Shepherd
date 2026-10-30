# Classifier rule data

Human-reviewable rules the device classifier loads at start-up (`go:embed`, in `internal/classify/rules/`). Everything here was
checked against public sources on **2026-10-30**; nothing is included on a guess. This file lists every rule
with its evidence, and `TestReadmeListsEveryRule` fails if a rule is added to the JSON without being
listed here.

| File | What it holds |
|---|---|
| `classes.json` | the device classes (the registry's device types), their suggested-group name and close relatives |
| `domains.json` | domain-suffix rules: a name a device looks up points at one or more classes |
| `vendors.json` | manufacturer priors, matched against the OUI vendor name as whole words (longest rule wins) |
| `asn.json` | ASN and ASN-organization hints, plus the shared CDN, cloud and backbone networks that carry no weight |
| `services.json` | mDNS service-type rules (must agree with `devices.ServiceTypeRules`; a test enforces it) |

## What a weight means

A weight is how strongly one observation points at a class, between 0 and 1. The rubric:

- **0.8 to 0.9**: a service or manufacturer that exists only for that kind of device (a camera maker's cloud, a speaker maker).
- **0.4 to 0.7**: a vendor site or platform used mostly by that class but also by people browsing (a router maker's website), or a platform that serves two classes.
- **0.1 to 0.35**: a general-purpose ecosystem (Apple services, Steam, a wearable maker's site that phones also visit).
- **ASN hints are capped at 0.4** (a test enforces it) and are scored with a further cap, so a network alone can never name a device.
- **Shared networks** (CDNs, clouds, backbones) carry no weight at all: they say nothing about the device.

The weights are judgments; the **evidence** column is what was verified. Both are open to correction: see
"Adding or correcting a rule" in `docs/CLASSIFY.md`.

## Evidence codes

| Code | Meaning | Source queried |
|---|---|---|
| E1 | the TLS certificate served for the domain names the vendor as its organization | the domain's own HTTPS endpoint |
| E2 | the DNS SOA contact or name servers sit in the vendor's own namespace | public DNS |
| E3 | the site's content, title or redirect is the vendor's product site | the domain's own HTTPS endpoint |
| E4 | the vendor's or platform's documentation lists the domain | Apple "Use Apple products on enterprise networks" (support.apple.com/101555); Microsoft "Manage connection endpoints for Windows 11" (learn.microsoft.com, windows/privacy); Android Enterprise network requirements (support.google.com/work/android/answer/10513641); Sony PS5 network ports (playstation.com support) |
| E5 | an address of the domain is announced by the vendor's own AS | RIPEstat `prefix-overview` |
| E6 | the WHOIS registrant names the vendor | public WHOIS |

ASN entries were checked with RIPEstat `as-overview` (holder name and whether the AS is announced), and
the DB-IP ASN database's field names and type (`DBIP-ASN-Lite (compat=GeoLite2-ASN)`) were checked by
opening the 2026-10 file.

## Left out on purpose

Candidates that could not be verified were dropped rather than guessed: Samsung TV domains
(`samsungcloudsolution.com`, `samsungotn.net` have a Samsung registrant but nothing public says what
they are for; `samsungacr.com`, `samsungads.com` and `lgsmartad.com` do not resolve), `easy4ip.com`
(no Dahua attribution found), `bamgrid.com`, `aiv-cdn.net`, `nflxvideo.net`, `nintendo.net`, `tuyaus.com`,
`tuyaeu.com`, `bose.io`, the MyQ domains, Kobo, and vendor priors for Amcrest, Raspberry Pi, Withings,
Ruckus and Canon. ASNs with no announcement today were not used (Spotify, Twitch, Nest Labs, Lutron,
Samsung Electronics, Ecobee, SimpliSafe). Many device makers (Sonos, Ring, Wyze, TP-Link) run entirely
on shared clouds and have no ASN of their own: that is why domains carry most of the weight.

## Domain rules

| Suffix | Classes (weight) | Reads as | Vendor | Evidence |
|---|---|---|---|---|
| `netflix.com` | tv 0.25, streaming box 0.15 | a streaming service | Netflix | E1 cert O=Netflix |
| `nflxso.net` | tv 0.25, streaming box 0.15 | a streaming service | Netflix | E2 SOA contact nicadmin.netflix.com |
| `nflxext.com` | tv 0.25, streaming box 0.15 | a streaming service | Netflix | E5 apex address announced by AS40027 (Netflix) |
| `disneyplus.com` | tv 0.25, streaming box 0.15 | a streaming service | Disney+ | E3 site is Disney+ |
| `dssott.com` | tv 0.25, streaming box 0.15 | a streaming service | Disney Streaming | E2 SOA contact dnsadmin.bamtechmedia.com (BAMTech, Disney Streaming) |
| `hulu.com` | tv 0.25, streaming box 0.15 | a streaming service | Hulu | E1 cert O=The Walt Disney Company, CN *.hulu.com |
| `hulustream.com` | tv 0.25, streaming box 0.15 | a streaming service | Hulu | E2 SOA contact dnsadmin.hulu.com |
| `hbomax.com` | tv 0.25, streaming box 0.15 | a streaming service | HBO Max | E3 site is HBO Max |
| `max.com` | tv 0.25, streaming box 0.15 | a streaming service | HBO Max | E3 redirects to hbomax.com |
| `primevideo.com` | tv 0.25, streaming box 0.15 | a streaming service | Prime Video | E6 WHOIS registrant Hostmaster, Amazon Legal Dept. |
| `peacocktv.com` | tv 0.25, streaming box 0.15 | a streaming service | Peacock | E1 cert O=NBCUniversal, LLC |
| `paramountplus.com` | tv 0.25, streaming box 0.15 | a streaming service | Paramount+ | E3 site is Paramount Plus |
| `pluto.tv` | tv 0.25, streaming box 0.15 | a streaming service | Pluto TV | E1 cert O=Paramount Global |
| `sling.com` | tv 0.25, streaming box 0.15 | a streaming service | Sling TV | E1 cert O=DISH Network Corporation |
| `tubi.tv` | tv 0.25, streaming box 0.15 | a streaming service | Tubi | E3 redirects to tubitv.com, free movies and TV |
| `plex.tv` | tv 0.30, streaming box 0.30, NAS/server 0.15 | a media-server service | Plex | E1 cert O=Plex GmbH |
| `roku.com` | streaming box 0.85, tv 0.30 | Roku's service | Roku | E3 site: Roku streams entertainment to your TV |
| `hik-connect.com` | camera 0.90 | a camera cloud service | Hikvision | E1 cert O=Hangzhou Hikvision Digital Technology |
| `ezvizlife.com` | camera 0.85, doorbell 0.10 | a camera cloud service | EZVIZ | E1 cert O=Hangzhou Ezviz Network |
| `ezviz.com` | camera 0.70, doorbell 0.10 | a camera cloud service | EZVIZ | E1 cert O=Hangzhou Ezviz Network; E3 site sells security cameras |
| `imoulife.com` | camera 0.80, doorbell 0.10 | a camera cloud service | Imou | E3 site sells Imou cameras and doorbells |
| `reolink.com` | camera 0.60 | a camera cloud service | Reolink | E3 site: Reolink security cameras |
| `wyzecam.com` | camera 0.85 | a camera cloud service | Wyze | E1 cert O=WYZE LABS, INC. |
| `foscam.com` | camera 0.70 | a camera cloud service | Foscam | E3 site: Foscam security and IP cameras |
| `arlo.com` | camera 0.70 | a camera cloud service | Arlo | E1 cert O=Arlo Technologies, Inc. |
| `blinkforhome.com` | camera 0.85, doorbell 0.10 | a camera cloud service | Blink | E3 site: Blink Smart Security |
| `dropcam.com` | camera 0.80, doorbell 0.10 | a camera cloud service | Nest Cam | E3 redirects to Google Store Nest cameras |
| `eufylife.com` | camera 0.45, doorbell 0.15, smart plug/sensor 0.15 | a smart-home camera service | eufy | E3 redirects to eufy.com, home security and smart-home devices |
| `ring.com` | doorbell 0.60, camera 0.30 | a doorbell cloud service | Ring | E3 site: Ring video doorbells and security cameras |
| `simplisafe.com` | smart-home hub 0.50, camera 0.30, doorbell 0.10 | a home-security service | SimpliSafe | E3 site: SimpliSafe home security systems |
| `nest.com` | thermostat 0.35, camera 0.30, smart-home hub 0.25, doorbell 0.10, speaker 0.10 | Google Nest | Google Nest | E3 redirects to Google Home and Nest devices |
| `tplinkcloud.com` | smart plug/sensor 0.55, camera 0.30 | a smart-home cloud service | TP-Link | E1 cert O=TP-Link Systems Inc. |
| `tapo.com` | camera 0.40, smart plug/sensor 0.40 | a smart-home cloud service | TP-Link Tapo | E3 site: Tapo smart devices |
| `tuya.com` | smart plug/sensor 0.75, smart-home hub 0.10 | a smart-device platform | Tuya | E3 site: Tuya Global AIoT Platform |
| `shelly.cloud` | smart plug/sensor 0.85 | a smart-device platform | Shelly | E3 redirects to shelly.com, smart-home automation |
| `meross.com` | smart plug/sensor 0.80 | a smart-device platform | Meross | E3 site: Meross smart plugs, sensors and switches |
| `meethue.com` | smart-home hub 0.80 | a smart-home platform | Philips Hue | E3 redirects to philips-hue.com |
| `ecobee.com` | thermostat 0.85 | a thermostat cloud | ecobee | E3 site: ecobee thermostats, cameras and sensors |
| `mytotalconnectcomfort.com` | thermostat 0.80 | a thermostat cloud | Resideo | E1 cert O=Resideo |
| `resideo.com` | thermostat 0.50, smart-home hub 0.20 | a thermostat cloud | Resideo | E1 cert O=Resideo Technologies; E3 site: smart thermostats |
| `smartthings.com` | smart-home hub 0.70 | a smart-home platform | SmartThings | E3 redirects to Samsung SmartThings |
| `nabucasa.com` | smart-home hub 0.85 | a smart-home platform | Home Assistant | E3 site: Nabu Casa, official Home Assistant products |
| `home-assistant.io` | smart-home hub 0.60, NAS/server 0.30 | a smart-home platform | Home Assistant | E3 site: Home Assistant |
| `lutron.com` | smart-home hub 0.50 | a smart-home platform | Lutron | E1 cert O=Lutron Electronics Co., Inc. |
| `sonos.com` | speaker 0.90 | a smart-speaker service | Sonos | E3 site: Sonos soundbars and headphones |
| `amazonalexa.com` | speaker 0.50, smart-home hub 0.15 | a smart-speaker service | Alexa | E1 cert CN www.stage-business.amazon.com (Amazon) |
| `playstation.net` | game console 0.90 | a game network | PlayStation | E4 Sony PS5 network-ports support page lists it |
| `sonyentertainmentnetwork.com` | game console 0.90 | a game network | PlayStation | E1 cert O=SONY INTERACTIVE ENTERTAINMENT LLC; E4 Sony support page lists it |
| `playstation.com` | game console 0.40 | a game network | PlayStation | E1 cert O=Sony Interactive Entertainment LLC |
| `xboxlive.com` | game console 0.85 | a game network | Xbox | E4 Microsoft endpoint documentation lists it |
| `xbox.com` | game console 0.40 | a game network | Xbox | E1 cert O=Microsoft Corporation |
| `nintendowifi.net` | game console 0.90 | a game network | Nintendo | E5 apex address announced by AS11278 (Nintendo) |
| `nintendo.com` | game console 0.40 | a game network | Nintendo | E1 cert O=Nintendo of America Inc. |
| `steampowered.com` | game console 0.30, laptop 0.40 | Steam | Valve | E3 site: Steam |
| `steamcontent.com` | game console 0.30, laptop 0.40 | Steam | Valve | E2 SOA contact in valvesoftware.com |
| `connectivitycheck.gstatic.com` | phone 0.45, tablet 0.15, tv 0.10 | Android network checks | Android | E4 Android Enterprise network requirements page lists it |
| `mtalk.google.com` | phone 0.30, tablet 0.10, laptop 0.10 | Google push messaging | Android | E4 Android Enterprise network requirements page lists it |
| `push.apple.com` | phone 0.20, laptop 0.15, tablet 0.10 | Apple push notifications | Apple | E4 Apple network-ports support page (101555) lists it |
| `icloud.com` | phone 0.15, laptop 0.10, tablet 0.05 | Apple services | Apple | E1 cert O=Apple Inc. |
| `apple.com` | phone 0.15, laptop 0.10, tablet 0.05 | Apple services | Apple | E1 cert O=Apple Inc. |
| `windowsupdate.com` | laptop 0.50 | Windows Update | Windows | E4 Microsoft Windows endpoint documentation lists it |
| `msftconnecttest.com` | laptop 0.45 | Windows network checks | Windows | E4 Microsoft Windows endpoint documentation lists it |
| `lgappstv.com` | tv 0.80 | a TV maker's service | LG | E1 cert O=LG Electronics Inc.; function inferred from the service name (LG Apps TV) |
| `lgtvsdp.com` | tv 0.80 | a TV maker's service | LG | E2 SOA/NS in lg.co.kr, WHOIS registrant LG Electronics; function inferred from the service name (LG TV SDP) |
| `vizio.com` | tv 0.50 | a TV maker's service | Vizio | E3 site: VIZIO smart TVs and soundbars |
| `hpeprint.com` | printer 0.70 | a printing service | HP | E1 cert O=HP Inc (HP ePrint) |
| `hpconnected.com` | printer 0.50 | a printing service | HP | E1 cert O=HP Inc |
| `epsonconnect.com` | printer 0.65 | a printing service | Epson | E1 cert O=SEIKO EPSON CORPORATION (Epson Connect) |
| `ui.com` | router/infrastructure 0.60, camera 0.15 | a networking vendor's service | Ubiquiti | E3 site: UniFi, Ubiquiti |
| `ubnt.com` | router/infrastructure 0.60, camera 0.15 | a networking vendor's service | Ubiquiti | E3 redirects to ui.com |
| `eero.com` | router/infrastructure 0.80 | a networking vendor's service | eero | E3 site: eero mesh WiFi routers |
| `netgear.com` | router/infrastructure 0.50 | a networking vendor's service | Netgear | E3 site: NETGEAR networking products |
| `linksys.com` | router/infrastructure 0.50 | a networking vendor's service | Linksys | E3 site: Linksys WiFi solutions |
| `mikrotik.com` | router/infrastructure 0.60 | a networking vendor's service | MikroTik | E1 cert O=SIA "Mikrotikls"; E3 site: routers |
| `tp-link.com` | router/infrastructure 0.45, smart plug/sensor 0.10 | a networking vendor's service | TP-Link | E3 site: TP-Link Wi-Fi and smart home |
| `zyxel.com` | router/infrastructure 0.50 | a networking vendor's service | Zyxel | E3 site: Zyxel networking |
| `synology.com` | NAS/server 0.60 | a NAS vendor's service | Synology | E3 site: Synology data management |
| `quickconnect.to` | NAS/server 0.85 | a NAS vendor's service | Synology | E3 site: Synology QuickConnect |
| `qnap.com` | NAS/server 0.60 | a NAS vendor's service | QNAP | E3 site: QNAP NAS and storage |
| `myqnapcloud.com` | NAS/server 0.85 | a NAS vendor's service | QNAP | E3 site: myQNAPcloud |
| `truenas.com` | NAS/server 0.70 | a NAS vendor's service | TrueNAS | E3 site: TrueNAS storage |
| `unraid.net` | NAS/server 0.70 | a NAS vendor's service | Unraid | E3 site: Unraid, OS for storage, Docker and VMs |
| `fitbit.com` | wearable 0.50 | a wearable maker's service | Fitbit | E3 redirects to Google Fitbit trackers and watches |
| `garmin.com` | wearable 0.30 | a wearable maker's service | Garmin | E1 cert CN *.garmin.com; E3 site: GPS-enabled sports and fitness products |
| `ouraring.com` | wearable 0.80 | a wearable maker's service | Oura | E3 site: Oura Ring |

## Vendor priors

| Match | Classes (weight) | Known for | Evidence |
|---|---|---|---|
| `hikvision` | camera 0.85 | IP cameras | E1 cert O=Hangzhou Hikvision Digital Technology (hik-connect.com); OUI name 'Hangzhou Hikvision Digital Technology' |
| `dahua` | camera 0.85 | IP cameras | E3 dahuasecurity.com: video-centric AIoT provider |
| `reolink` | camera 0.90 | security cameras | E3 reolink.com: security cameras and systems |
| `wyze` | camera 0.55, smart plug/sensor 0.20 | cameras and smart-home gadgets | E3 wyze.com: smart home security cameras and devices |
| `arlo` | camera 0.90 | security cameras | E1 cert O=Arlo Technologies, Inc. |
| `blink` | camera 0.80, doorbell 0.10 | security cameras | OUI name 'Blink by Amazon'; E3 blinkforhome.com: Blink Smart Security |
| `sonos` | speaker 0.85 | smart speakers | E3 sonos.com: soundbars, speakers, headphones |
| `bose` | speaker 0.55 | speakers and headphones | E3 bose.com: headphones, earbuds, speakers, soundbars |
| `roku` | streaming box 0.75, tv 0.20 | streaming players | E3 roku.com: streaming to your TV |
| `vizio` | tv 0.85 | TVs | E3 vizio.com: smart TVs and soundbars |
| `tcl` | tv 0.45, phone 0.15 | TVs | OUI names 'TCL' and 'Huizhou TCL Communication'; E3 tcl.com |
| `hisense` | tv 0.50 | TVs and appliances | E3 hisense.com: TVs, refrigerators, air conditioners |
| `lg electronics` | tv 0.35, phone 0.10 | TVs and appliances | E3 lg.com: home entertainment and appliances |
| `brother` | printer 0.70 | printers | E3 brother-usa.com: printers, sewing machines, label makers |
| `seiko epson` | printer 0.80 | printers | E1 cert O=SEIKO EPSON CORPORATION (epsonconnect.com) |
| `lexmark` | printer 0.90 | printers | E3 lexmark.com: enterprise printers |
| `xerox` | printer 0.85 | printers | E3 xerox.com: digital printing technologies |
| `ricoh` | printer 0.75 | printers and copiers | E3 ricoh.com (document technology company; weaker evidence) |
| `hewlett packard enterprise` | neutral |  | neutral on purpose: the enterprise company is not the printer and PC maker, so it must not inherit the broader HP rule |
| `hewlett packard` | printer 0.40, laptop 0.30 | printers and PCs | E3 hp.com: laptops, desktops, printers |
| `nintendo` | game console 0.90 | game consoles | E3 nintendo.com: Switch systems and video games |
| `sony interactive` | game console 0.90 | game consoles | E3 playstation.com: Sony Interactive Entertainment, PS5 |
| `sony computer entertainment` | game console 0.85 | game consoles | OUI name; E3 playstation.com: Sony Interactive Entertainment |
| `valve` | game console 0.60, laptop 0.10 | Steam game hardware | OUI name 'Valve'; E3 steampowered.com |
| `microsoft` | laptop 0.30, game console 0.15 | PCs and game consoles | E4 Microsoft endpoint docs cover Windows and Xbox |
| `espressif` | smart plug/sensor 0.45, smart-home hub 0.10 | chips inside smart plugs and sensors | E3 espressif.com: wireless SoCs for IoT |
| `tuya` | smart plug/sensor 0.70 | smart-plug and sensor modules | E3 tuya.com: AIoT platform for smart devices |
| `shelly` | smart plug/sensor 0.80 | smart relays and plugs | E3 shelly.com: smart-home automation |
| `meross` | smart plug/sensor 0.80 | smart plugs and switches | E3 meross.com: smart plugs, sensors, switches |
| `signify` | smart-home hub 0.65 | Philips Hue lighting | E3 signify.com: connected lighting systems |
| `ecobee` | thermostat 0.85 | thermostats | E3 ecobee.com: thermostats, cameras, sensors |
| `resideo` | thermostat 0.55, smart-home hub 0.15 | thermostats | E3 resideo.com: smart thermostats, cameras |
| `lutron` | smart-home hub 0.50 | lighting controls | E1 cert O=Lutron Electronics Co., Inc.; function from product knowledge (weaker evidence) |
| `netatmo` | thermostat 0.35, smart plug/sensor 0.40 | thermostats and weather sensors | E3 netatmo.com: thermostat, cameras, weather station |
| `fitbit` | wearable 0.60 | fitness trackers | E3 fitbit.com: fitness trackers and smartwatches |
| `garmin` | wearable 0.50 | fitness and GPS watches | E3 garmin.com: sports and fitness products |
| `oura` | wearable 0.85 | smart rings | E3 ouraring.com: Oura Ring |
| `eero` | router/infrastructure 0.90 | mesh Wi-Fi routers | E3 eero.com: mesh WiFi |
| `ubiquiti` | router/infrastructure 0.60, camera 0.10 | network gear | E3 ui.com: UniFi networking |
| `netgear` | router/infrastructure 0.70 | routers and switches | E3 netgear.com: networking products |
| `tp-link` | router/infrastructure 0.60, smart plug/sensor 0.15, camera 0.10 | routers and smart-home gear | E3 tp-link.com: Wi-Fi and smart home |
| `cisco-linksys` | router/infrastructure 0.80 | routers | E3 linksys.com: WiFi solutions |
| `linksys` | router/infrastructure 0.80 | routers | E3 linksys.com: WiFi solutions |
| `zyxel` | router/infrastructure 0.80 | network gear | E3 zyxel.com: networking |
| `avm` | router/infrastructure 0.85 | Fritz!Box routers | E3 avm.de: FRITZ! internet and home-network products |
| `sagemcom` | router/infrastructure 0.60 | broadband gateways | E3 sagemcom.com: broadband solutions |
| `cisco meraki` | router/infrastructure 0.85 | network gear | OUI name; Cisco Meraki is a networking brand (weaker evidence) |
| `juniper` | router/infrastructure 0.80 | network gear | E3 juniper.net: AI-native networking |
| `synology` | NAS/server 0.85 | NAS storage | E3 synology.com: data management and storage |
| `qnap` | NAS/server 0.85 | NAS storage | E3 qnap.com: NAS and storage |
| `apple` | phone 0.25, laptop 0.20, tablet 0.10, tv 0.05 | phones and computers | E1 cert O=Apple Inc.; deliberately weak: Apple makes many device kinds |

## ASNs

| ASN | Holder (RIPEstat, 2026-10-30) | Hint | Reads as |
|---|---|---|---|
| AS2906 | AS-SSI - Netflix Streaming Services Inc. | tv 0.20, streaming box 0.15 | a streaming network |
| AS40027 | NETFLIX-ASN - Netflix Streaming Services Inc. | tv 0.20, streaming box 0.15 | a streaming network |
| AS394557 | ROKU - Roku Inc. | streaming box 0.35, tv 0.10 | Roku's network |
| AS23286 | HULU - Hulu, LLC | tv 0.15, streaming box 0.10 | a streaming network |
| AS21478 | PLEX Plex BV | tv 0.10, streaming box 0.10, NAS/server 0.10 | a media-server network |
| AS11278 | NINTENDO - Nintendo Of America inc. | game console 0.35 | a game network |
| AS32590 | VALVE-CORPORATION - Valve Corporation | game console 0.20, laptop 0.15 | Steam's network |
| AS26324 | GARMIN-ASN-1 - GARMIN INTERNATIONAL INC. | wearable 0.25 | a wearable maker's network |
| AS140079 | GARMININTERNATIONAL-AS-AP - Garmin International Inc | wearable 0.25 | a wearable maker's network |
| AS714 | APPLE-ENGINEERING - Apple Inc. | phone 0.10, laptop 0.08, tablet 0.04 | Apple's network |
| AS6185 | APPLE-AUSTIN - Apple Inc. | phone 0.10, laptop 0.08, tablet 0.04 | Apple's network |
| AS15169 | GOOGLE - Google LLC | shared, no weight |  |
| AS36040 | YOUTUBE - Google LLC | shared, no weight |  |
| AS396982 | GOOGLE-CLOUD-PLATFORM - Google LLC | shared, no weight |  |
| AS16509 | AMAZON-02 - Amazon.com, Inc. | shared, no weight |  |
| AS14618 | AMAZON-AES - Amazon.com, Inc. | shared, no weight |  |
| AS13335 | CLOUDFLARENET - Cloudflare, Inc. | shared, no weight |  |
| AS20940 | AKAMAI-ASN1 Akamai International B.V. | shared, no weight |  |
| AS12222 | AKAMAI - Akamai Technologies, Inc. | shared, no weight |  |
| AS16625 | AKAMAI-AS - Akamai Technologies, Inc. | shared, no weight |  |
| AS21342 | AKAMAI-ASN2 Akamai International B.V. | shared, no weight |  |
| AS34164 | AKAMAI-LON Akamai International B.V. | shared, no weight |  |
| AS63949 | AKAMAI-LINODE-AP - Akamai Connected Cloud | shared, no weight |  |
| AS54113 | FASTLY - Fastly, Inc. | shared, no weight |  |
| AS14210 | EDGECAST - Edgecast Inc. | shared, no weight |  |
| AS8075 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation | shared, no weight |  |
| AS8068 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation | shared, no weight |  |
| AS8069 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation | shared, no weight |  |
| AS32934 | FACEBOOK - Facebook, Inc. | shared, no weight |  |
| AS19551 | INCAPSULA - Incapsula Inc | shared, no weight |  |
| AS14061 | DIGITALOCEAN-ASN - DigitalOcean, LLC | shared, no weight |  |
| AS24940 | HETZNER-AS Hetzner Online GmbH | shared, no weight |  |
| AS16276 | OVH OVH SAS | shared, no weight |  |
| AS20473 | AS-VULTR - The Constant Company, LLC | shared, no weight |  |
| AS45102 | ALIBABA-CN-NET - Alibaba (US) Technology Co., Ltd. | shared, no weight |  |
| AS37963 | ALIBABA-CN-NET - Hangzhou Alibaba Advertising Co.,Ltd. | shared, no weight |  |
| AS45090 | TENCENT-NET-AP - Shenzhen Tencent Computer Systems Company Limited | shared, no weight |  |
| AS136907 | HWCLOUDS-AS-AP - HUAWEI CLOUDS | shared, no weight |  |
| AS55990 | HWCSNET - Huawei Cloud Service data center | shared, no weight |  |
| AS3356 | LEVEL3 - Level 3 Parent, LLC | shared, no weight |  |
| AS396190 | LEASEWEB-USA-SEA - Leaseweb USA, Inc. | shared, no weight |  |
| AS21859 | ZEN-ECN - Zenlayer Inc | shared, no weight |  |

## ASN organization keywords

Matched as whole words, case-insensitively, against the organization name the ASN database reports.

| Keyword | Hint | Reads as | Evidence |
|---|---|---|---|
| `netflix` | tv 0.20, streaming box 0.15 | a streaming network | holder 'Netflix Streaming Services Inc.' (AS2906, AS40027) |
| `roku` | streaming box 0.35, tv 0.10 | Roku's network | holder 'Roku Inc.' (AS394557) |
| `hulu` | tv 0.15, streaming box 0.10 | a streaming network | holder 'Hulu, LLC' (AS23286) |
| `nintendo` | game console 0.35 | a game network | holder 'Nintendo Of America inc.' (AS11278) |
| `valve corporation` | game console 0.20, laptop 0.15 | Steam's network | holder 'Valve Corporation' (AS32590) |
| `garmin` | wearable 0.25 | a wearable maker's network | holders 'GARMIN INTERNATIONAL INC.' (AS26324), 'Garmin International Inc' (AS140079) |
| `akamai` | shared, no weight |  | holder 'Akamai Technologies, Inc.' (AS12222); shared CDN or cloud network |
| `cloudflare` | shared, no weight |  | holder 'Cloudflare, Inc.' (AS13335); shared CDN or cloud network |
| `amazon` | shared, no weight |  | holder 'Amazon.com, Inc.' (AS16509, AS14618); shared CDN or cloud network |
| `google` | shared, no weight |  | holder 'Google LLC' (AS15169); shared CDN or cloud network |
| `microsoft` | shared, no weight |  | holder 'Microsoft Corporation' (AS8075); shared CDN or cloud network |
| `fastly` | shared, no weight |  | holder 'Fastly, Inc.' (AS54113); shared CDN or cloud network |
| `edgecast` | shared, no weight |  | holder 'Edgecast Inc.' (AS14210); shared CDN or cloud network |
| `digitalocean` | shared, no weight |  | holder 'DigitalOcean, LLC' (AS14061); shared CDN or cloud network |
| `hetzner` | shared, no weight |  | holder 'Hetzner Online GmbH' (AS24940); shared CDN or cloud network |
| `ovh` | shared, no weight |  | holder 'OVH SAS' (AS16276); shared CDN or cloud network |
| `alibaba` | shared, no weight |  | holder 'Alibaba (US) Technology Co., Ltd.' (AS45102); shared CDN or cloud network |
| `tencent` | shared, no weight |  | holder 'Shenzhen Tencent Computer Systems Company Limited' (AS45090); shared CDN or cloud network |
| `leaseweb` | shared, no weight |  | holder 'Leaseweb USA, Inc.' (AS396190); shared CDN or cloud network |
| `zenlayer` | shared, no weight |  | holder 'Zenlayer Inc' (AS21859); shared CDN or cloud network |
| `the constant company` | shared, no weight |  | holder 'The Constant Company, LLC' (AS20473); shared CDN or cloud network |
| `incapsula` | shared, no weight |  | holder 'Incapsula Inc' (AS19551); shared CDN or cloud network |

## mDNS services

These mirror `devices.ServiceTypeRules` (the registry's own table) with a weight each.

| Service | Classes (weight) | Reads as |
|---|---|---|
| `_ipp` | printer 0.90 | a printing service |
| `_ipps` | printer 0.90 | a printing service |
| `_printer` | printer 0.90 | a printing service |
| `_pdl-datastream` | printer 0.90 | a printing service |
| `_scanner` | printer 0.80 | a scanning service |
| `_uscan` | printer 0.80 | a scanning service |
| `_rtsp` | camera 0.50 | a video-streaming service |
| `_axis-video` | camera 0.90 | a camera video service |
| `_nvstream` | game console 0.50 | a game-streaming service |
| `_sonos` | speaker 0.90 | the Sonos speaker service |
| `_spotify-connect` | speaker 0.40 | Spotify Connect |
| `_raop` | speaker 0.50 | AirPlay audio |
| `_hap` | smart-home hub 0.60 | HomeKit |
| `_homekit` | smart-home hub 0.60 | HomeKit |
| `_matter` | smart-home hub 0.70 | Matter |
| `_matterc` | smart-home hub 0.60 | Matter commissioning |
| `_meshcop` | smart-home hub 0.50 | a Thread border router |
| `_hue` | smart-home hub 0.80 | Philips Hue |
| `_googlecast` | tv 0.40, speaker 0.20 | Google Cast |
| `_airplay` | tv 0.40, speaker 0.20 | AirPlay video |

#[derive(Clone, Copy)]
pub enum FeedFormat {
    UrlhausZipJson,
    UrlhausJson,
    PhishuntJson,
    StringArrayJson,
    MetamaskJson,
    TweetFeedJson,
    SpmediaJson,
    PhishTankGzipJson,
    MispDirectory,
    MispManifest,
    HostsFile,
    PlainLines,
    TarGzLines,
    ViribackCsv,
    Adguard,
}

#[derive(Clone, Copy)]
pub struct FeedSource {
    pub name: &'static str,
    pub url: &'static str,
    pub format: FeedFormat,
    pub threat_type: &'static str,
    pub default_indicator_type: &'static str,
}

pub fn feed_sources() -> Vec<FeedSource> {
    vec![
        FeedSource {
            name: "urlhaus_online",
            url: "https://urlhaus.abuse.ch/downloads/json_online/",
            format: FeedFormat::UrlhausJson,
            threat_type: "malware_download",
            default_indicator_type: "url",
        },
        FeedSource {
            name: "phishunt",
            url: "https://phishunt.io/feed.json",
            format: FeedFormat::PhishuntJson,
            threat_type: "phishing",
            default_indicator_type: "url",
        },
        FeedSource {
            name: "destroylist",
            url: "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json",
            format: FeedFormat::StringArrayJson,
            threat_type: "phishing,crypto_drainer",
            default_indicator_type: "domain",
        },
        FeedSource {
            name: "metamask_eth_phishing",
            url: "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
            format: FeedFormat::MetamaskJson,
            threat_type: "crypto_drainer",
            default_indicator_type: "domain",
        },
        FeedSource {
            name: "spmedia_crypto",
            url: "https://raw.githubusercontent.com/spmedia/Crypto-Scam-and-Crypto-Phishing-Threat-Intel-Feed/refs/heads/main/detected_urls.json",
            format: FeedFormat::SpmediaJson,
            threat_type: "crypto_drainer,pig_butchering",
            default_indicator_type: "domain",
        },
        FeedSource {
            name: "phishtank",
            url: "http://data.phishtank.com/data/online-valid.json.gz",
            format: FeedFormat::PhishTankGzipJson,
            threat_type: "phishing",
            default_indicator_type: "url",
        },
        FeedSource {
            name: "threatfox_misp",
            url: "https://threatfox.abuse.ch/downloads/misp/",
            format: FeedFormat::MispDirectory,
            threat_type: "botnet_cc,malware_download",
            default_indicator_type: "domain",
        },
        FeedSource {
            name: "curbengh_phishing_filter",
            url: "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt",
            format: FeedFormat::Adguard,
            threat_type: "phishing",
            default_indicator_type: "domain",
        },
        FeedSource {
            name: "blackbook",
            url: "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
            format: FeedFormat::PlainLines,
            threat_type: "malware_download,botnet_cc",
            default_indicator_type: "domain",
        },
        /* Disabled by default: useful, but slower/heavier or lower signal for URL checks.
        FeedSource { name: "urlhaus", url: "https://urlhaus.abuse.ch/downloads/json/", format: FeedFormat::UrlhausZipJson, threat_type: "malware_download", default_indicator_type: "url" },
        FeedSource { name: "destroylist_community", url: "https://raw.githubusercontent.com/phishdestroy/destroylist/main/community/blocklist.json", format: FeedFormat::StringArrayJson, threat_type: "phishing,crypto_drainer", default_indicator_type: "domain" },
        FeedSource { name: "tweetfeed_week", url: "https://api.tweetfeed.live/v1/week", format: FeedFormat::TweetFeedJson, threat_type: "phishing,scam", default_indicator_type: "domain" },
        FeedSource { name: "infoblox_misp", url: "https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp/manifest.json", format: FeedFormat::MispManifest, threat_type: "botnet_cc,phishing,pig_butchering", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_phishing", url: "https://blocklistproject.github.io/Lists/phishing.txt", format: FeedFormat::HostsFile, threat_type: "phishing", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_malware", url: "https://blocklistproject.github.io/Lists/malware.txt", format: FeedFormat::HostsFile, threat_type: "malware_download", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_scam", url: "https://blocklistproject.github.io/Lists/scam.txt", format: FeedFormat::HostsFile, threat_type: "scam", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_fraud", url: "https://blocklistproject.github.io/Lists/fraud.txt", format: FeedFormat::HostsFile, threat_type: "fraud", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_crypto", url: "https://blocklistproject.github.io/Lists/crypto.txt", format: FeedFormat::HostsFile, threat_type: "crypto_drainer", default_indicator_type: "domain" },
        FeedSource { name: "blocklistproject_ransomware", url: "https://blocklistproject.github.io/Lists/ransomware.txt", format: FeedFormat::HostsFile, threat_type: "ransomware", default_indicator_type: "domain" },
        FeedSource { name: "phishing_database_links", url: "https://phish.co.za/latest/ALL-phishing-links.lst", format: FeedFormat::PlainLines, threat_type: "phishing", default_indicator_type: "url" },
        FeedSource { name: "phishing_database_domains", url: "https://phish.co.za/latest/ALL-phishing-domains.tar.gz", format: FeedFormat::TarGzLines, threat_type: "phishing", default_indicator_type: "domain" },
        FeedSource { name: "viriback", url: "https://tracker.viriback.com/dump.php", format: FeedFormat::ViribackCsv, threat_type: "botnet_cc", default_indicator_type: "url" },
        FeedSource { name: "curbengh_urlhaus_filter", url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt", format: FeedFormat::Adguard, threat_type: "malware_download", default_indicator_type: "domain" },
        FeedSource { name: "phishing_army", url: "https://phishing.army/download/phishing_army_blocklist.txt", format: FeedFormat::PlainLines, threat_type: "phishing", default_indicator_type: "domain" },
        FeedSource { name: "phishing_army_extended", url: "https://phishing.army/download/phishing_army_blocklist_extended.txt", format: FeedFormat::PlainLines, threat_type: "phishing", default_indicator_type: "domain" },
        FeedSource { name: "circl_osint_misp", url: "https://www.circl.lu/doc/misp/feed-osint/", format: FeedFormat::MispDirectory, threat_type: "threat_intel", default_indicator_type: "domain" },
        */
    ]
}

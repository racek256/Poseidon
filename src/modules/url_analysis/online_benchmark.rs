use std::time::Duration;

use crate::modules::url_analysis::online::analyse_online;

const DETECTION_THRESHOLD: u8 = 60;

struct Case {
    url: &'static str,
    expected_impersonation: bool,
    label: &'static str,
}

pub fn run_online_brand_benchmark() {
    let cases = benchmark_cases();
    let mut true_positive = 0;
    let mut true_negative = 0;
    let mut false_positive = 0;
    let mut false_negative = 0;
    let mut total_time = Duration::default();
    let mut dns_time = Duration::default();
    let mut whois_time = Duration::default();
    let mut http_time = Duration::default();
    let mut misses = Vec::new();

    for case in cases {
        let result = analyse_online(case.url);
        let detected = result.score >= DETECTION_THRESHOLD;
        total_time += result.timings.total;
        dns_time += result.timings.dns;
        whois_time += result.timings.whois;
        http_time += result.timings.http_page;

        println!(
            "case={} expected={} detected={} score={} total_ms={:.1} dns_ms={:.1} whois_ms={:.1} http_ms={:.1}",
            case.label,
            case.expected_impersonation,
            detected,
            result.score,
            result.timings.total.as_secs_f64() * 1000.0,
            result.timings.dns.as_secs_f64() * 1000.0,
            result.timings.whois.as_secs_f64() * 1000.0,
            result.timings.http_page.as_secs_f64() * 1000.0,
        );

        match (case.expected_impersonation, detected) {
            (true, true) => true_positive += 1,
            (false, false) => true_negative += 1,
            (false, true) => {
                false_positive += 1;
                misses.push((case.label, case.url, result.score, result.reasons));
            }
            (true, false) => {
                false_negative += 1;
                misses.push((case.label, case.url, result.score, result.reasons));
            }
        }
    }

    let total = cases.len();
    let correct = true_positive + true_negative;
    let accuracy = ratio(correct, total);
    let precision = ratio(true_positive, true_positive + false_positive);
    let recall = ratio(true_positive, true_positive + false_negative);
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    println!("online brand impersonation benchmark");
    println!("cases: {total}");
    println!("threshold: score >= {DETECTION_THRESHOLD}");
    println!("accuracy: {:.2}%", accuracy * 100.0);
    println!("precision: {:.2}%", precision * 100.0);
    println!("recall: {:.2}%", recall * 100.0);
    println!("f1: {:.2}%", f1 * 100.0);
    println!("tp={true_positive} tn={true_negative} fp={false_positive} fn={false_negative}");
    println!(
        "avg total ms/url: {:.1}",
        total_time.as_secs_f64() * 1000.0 / total as f64
    );
    println!(
        "avg dns ms/url: {:.1}",
        dns_time.as_secs_f64() * 1000.0 / total as f64
    );
    println!(
        "avg whois ms/url: {:.1}",
        whois_time.as_secs_f64() * 1000.0 / total as f64
    );
    println!(
        "avg http ms/url: {:.1}",
        http_time.as_secs_f64() * 1000.0 / total as f64
    );

    if !misses.is_empty() {
        println!("misses:");
        for (label, url, score, reasons) in misses {
            println!(
                "- label={label} score={score} url={url} reasons={}",
                reasons.join(" | ")
            );
        }
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn benchmark_cases() -> &'static [Case] {
    &[
        Case {
            url: "https://accounts.google.com/signin",
            expected_impersonation: false,
            label: "official google",
        },
        Case {
            url: "https://paypal.com/signin",
            expected_impersonation: false,
            label: "official paypal",
        },
        Case {
            url: "https://github.com/login",
            expected_impersonation: false,
            label: "official github",
        },
        Case {
            url: "https://support.apple.com/apple-id",
            expected_impersonation: false,
            label: "official apple support",
        },
        Case {
            url: "https://learn.microsoft.com/en-us/entra/identity/",
            expected_impersonation: false,
            label: "official microsoft docs",
        },
        Case {
            url: "https://aws.amazon.com/console/",
            expected_impersonation: false,
            label: "official amazon aws",
        },
        Case {
            url: "https://help.instagram.com/",
            expected_impersonation: false,
            label: "official instagram help",
        },
        Case {
            url: "https://blog.example.com/how-to-secure-your-paypal-account",
            expected_impersonation: false,
            label: "benign article path",
        },
        Case {
            url: "https://example.com/account/login",
            expected_impersonation: false,
            label: "generic login",
        },
        Case {
            url: "https://docs.example.com/microsoft-login-integration-guide",
            expected_impersonation: false,
            label: "benign docs path",
        },
        Case {
            url: "https://shop.example.com/apple-phone-case",
            expected_impersonation: false,
            label: "benign apple product path",
        },
        Case {
            url: "https://my-project.vercel.app",
            expected_impersonation: false,
            label: "normal vercel tenant",
        },
        Case {
            url: "https://paypal-login.vercel.app",
            expected_impersonation: true,
            label: "paypal hosting",
        },
        Case {
            url: "https://paypal.com.secure-login.example.net",
            expected_impersonation: true,
            label: "paypal subdomain",
        },
        Case {
            url: "https://paypa1.com/login",
            expected_impersonation: true,
            label: "paypal typo",
        },
        Case {
            url: "http://paypal.cardpaysecurity.org/login/k3ZXZz5PrN87W8YYvf98PC7tyGARWWwY5VEA=4BQ==7R1ZOR1ZbaFtYUF5Z/itrbAUX3V4NnCpTUNsEnK9rZkxcrOcHP/",
            expected_impersonation: true,
            label: "openphish paypal",
        },
        Case {
            url: "https://facebook-id9875314.invoice-ads-setting.com/",
            expected_impersonation: true,
            label: "openphish facebook",
        },
        Case {
            url: "http://update-billing-netflxx.weforweb.ro/",
            expected_impersonation: true,
            label: "openphish netflix typo",
        },
        Case {
            url: "https://netflix-clone-five-iota.vercel.app/",
            expected_impersonation: true,
            label: "openphish netflix hosting",
        },
        Case {
            url: "https://www.amazonpk-clone.vercel.app/",
            expected_impersonation: true,
            label: "openphish amazon hosting",
        },
        Case {
            url: "https://metamask-verify.qzz.io",
            expected_impersonation: true,
            label: "metamask hosting",
        },
        Case {
            url: "https://meta-astra.pages.dev/login",
            expected_impersonation: true,
            label: "openphish meta pages",
        },
        Case {
            url: "https://inc-icloudlocation.com/expire/?5",
            expected_impersonation: true,
            label: "openphish icloud location",
        },
        Case {
            url: "http://crypto-web3ledgervault.com/wallet.html",
            expected_impersonation: true,
            label: "openphish ledger wallet",
        },
        Case {
            url: "https://t-mobile.bwslxc.top/pay/",
            expected_impersonation: true,
            label: "openphish tmobile pay",
        },
        Case {
            url: "http://guide-liveledgr-faq.pages.dev/",
            expected_impersonation: true,
            label: "openphish ledger typo hosting",
        },
        Case {
            url: "https://barclays-banking.net/landing/form/8dafd984-7597-468f-8843-b4c566563ab5",
            expected_impersonation: true,
            label: "openphish barclays banking",
        },
    ]
}

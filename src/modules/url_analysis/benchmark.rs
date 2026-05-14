use std::time::Instant;

use crate::modules::url_analysis::brand;

const DETECTION_THRESHOLD: u8 = 45;
const SPEED_ITERATIONS: usize = 1_000;

struct Case {
    url: &'static str,
    expected_impersonation: bool,
    label: &'static str,
}

pub fn run_brand_benchmark() {
    let cases = benchmark_cases();
    let started = Instant::now();

    let mut true_positive = 0;
    let mut true_negative = 0;
    let mut false_positive = 0;
    let mut false_negative = 0;
    let mut misses = Vec::new();

    for case in cases {
        let result = brand::analyse(case.url);
        let detected = result.score >= DETECTION_THRESHOLD;

        match (case.expected_impersonation, detected) {
            (true, true) => true_positive += 1,
            (false, false) => true_negative += 1,
            (false, true) => {
                false_positive += 1;
                misses.push((case, result.score, result.reasons));
            }
            (true, false) => {
                false_negative += 1;
                misses.push((case, result.score, result.reasons));
            }
        }
    }

    let elapsed = started.elapsed();
    let total = cases.len();
    let correct = true_positive + true_negative;
    let accuracy = correct as f64 / total as f64;
    let precision = ratio(true_positive, true_positive + false_positive);
    let recall = ratio(true_positive, true_positive + false_negative);
    let f1 = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    let speed_started = Instant::now();
    for _ in 0..SPEED_ITERATIONS {
        for case in cases {
            let _ = brand::analyse(case.url);
        }
    }
    let speed_elapsed = speed_started.elapsed();
    let total_ops = SPEED_ITERATIONS * total;
    let micros_per_url = speed_elapsed.as_micros() as f64 / total_ops as f64;

    println!("brand impersonation benchmark");
    println!("cases: {total}");
    println!("threshold: score >= {DETECTION_THRESHOLD}");
    println!("accuracy: {:.2}%", accuracy * 100.0);
    println!("precision: {:.2}%", precision * 100.0);
    println!("recall: {:.2}%", recall * 100.0);
    println!("f1: {:.2}%", f1 * 100.0);
    println!("tp={true_positive} tn={true_negative} fp={false_positive} fn={false_negative}");
    println!("single pass: {elapsed:?}");
    println!("speed loop: {total_ops} urls in {speed_elapsed:?} ({micros_per_url:.2} us/url)");

    if !misses.is_empty() {
        println!("misses:");
        for (case, score, reasons) in misses {
            println!(
                "- label={} expected={} score={} url={} reasons={}",
                case.label,
                case.expected_impersonation,
                score,
                case.url,
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
            url: "https://paypal-login.vercel.app",
            expected_impersonation: true,
            label: "brand tenant on hosting",
        },
        Case {
            url: "https://paypal.com.secure-login.example.net",
            expected_impersonation: true,
            label: "brand in subdomain",
        },
        Case {
            url: "https://microsoft-verify-account.example.com",
            expected_impersonation: true,
            label: "brand plus verify",
        },
        Case {
            url: "https://appleid-login-security.example.org",
            expected_impersonation: true,
            label: "apple id lure",
        },
        Case {
            url: "https://paypa1.com/login",
            expected_impersonation: true,
            label: "paypal typo",
        },
        Case {
            url: "https://micros0ft-support.example.net/account",
            expected_impersonation: true,
            label: "microsoft typo subdomain",
        },
        Case {
            url: "https://coinbase-wallet-update.net",
            expected_impersonation: true,
            label: "crypto wallet lure",
        },
        Case {
            url: "https://metamask-verify.qzz.io",
            expected_impersonation: true,
            label: "wallet on hosting",
        },
        Case {
            url: "https://docusign-secure-invoice.pages.dev",
            expected_impersonation: true,
            label: "document signing lure",
        },
        Case {
            url: "https://accounts-google.com/signin",
            expected_impersonation: true,
            label: "google account lure",
        },
        Case {
            url: "http://paypal.cardpaysecurity.org/login/k3ZXZz5PrN87W8YYvf98PC7tyGARWWwY5VEA=4BQ==7R1ZOR1ZbaFtYUF5Z/itrbAUX3V4NnCpTUNsEnK9rZkxcrOcHP/",
            expected_impersonation: true,
            label: "openphish paypal cardpaysecurity",
        },
        Case {
            url: "http://update-billing-netflxx.weforweb.ro/",
            expected_impersonation: true,
            label: "openphish netflix typo",
        },
        Case {
            url: "https://facebook-id9875314.invoice-ads-setting.com/",
            expected_impersonation: true,
            label: "openphish facebook ad invoice",
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
            url: "https://microsoft.account.trustedentity.com/http/microsoft.authorised-support.com/new-account/EOzAFbYj1bjLmgufSIlKJJR9Kpvsy5kc3UkY=3Ag==5WFxWR1pGWlNBallaUlxbakJcQV1qRVRGRkJaR1E=/6Xx5KG1mKRNjeU3rSnC8diFTM7R4V1de/",
            expected_impersonation: true,
            label: "openphish microsoft account",
        },
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
            url: "https://support.apple.com/apple-id",
            expected_impersonation: false,
            label: "official apple support",
        },
        Case {
            url: "https://github.com/login",
            expected_impersonation: false,
            label: "official github",
        },
        Case {
            url: "https://blog.example.com/how-to-secure-your-paypal-account",
            expected_impersonation: false,
            label: "benign article path",
        },
        Case {
            url: "https://docs.example.com/microsoft-login-integration-guide",
            expected_impersonation: false,
            label: "benign docs path",
        },
        Case {
            url: "https://shop.example.com/apple-phone-case",
            expected_impersonation: false,
            label: "common word commerce",
        },
        Case {
            url: "https://my-project.vercel.app",
            expected_impersonation: false,
            label: "normal hosting tenant",
        },
        Case {
            url: "https://status.netlify.app",
            expected_impersonation: false,
            label: "normal hosting status",
        },
        Case {
            url: "https://example.com/account/login",
            expected_impersonation: false,
            label: "generic login no brand",
        },
    ]
}

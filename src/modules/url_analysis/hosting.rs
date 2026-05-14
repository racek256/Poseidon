pub fn hosting_provider_domain(registrable_domain: &str) -> Option<&'static str> {
    HOSTING_PROVIDER_DOMAINS
        .iter()
        .copied()
        .find(|domain| registrable_domain == *domain)
}

const HOSTING_PROVIDER_DOMAINS: &[&str] = &[
    "vercel.app",
    "netlify.app",
    "github.io",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "replit.app",
    "glitch.me",
    "surge.sh",
    "ngrok-free.app",
    "qzz.io",
];

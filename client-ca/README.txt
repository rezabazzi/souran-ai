Souran AI Network Server — client trust bundle

Install souran-dns-ca.crt as a trusted ROOT CA, then point the
client's DNS at this resolver using DoT or DoH.

  Android : Settings > Private DNS > Custom host
            host = mordaddns.ir  (no port field is offered;
            Android always uses 853/DoT)
            CA must be installed under Settings > Security >
            Encryption & credentials > Install a certificate >
            CA certificate.
  Windows : Settings > Network & internet > Wi-Fi > DNS server
            assignment > Manual > <IP>, DNS over HTTPS = On
            (Automatic certificate validation requires the CA
             in Trusted Root Certification Authorities.)
  macOS   : System Settings > Network > Details > DNS
            add <IP>; install the CA in Keychain Access as
            'Always Trust'.
  Linux   : systemd-resolved or /etc/resolv.conf -> <IP>.

Leaf certificate SANs:
      DNS:mordaddns.ir, DNS:dns.mordaddns.ir, DNS:cafenetmordad.ir, DNS:dns.cafenetmordad.ir, DNS:sitet.top, DNS:dns.sitet.top, DNS:souran.local, DNS:localhost, IP Address:127.0.0.1, IP Address:10.103.26.86, IP Address:10.66.66.1

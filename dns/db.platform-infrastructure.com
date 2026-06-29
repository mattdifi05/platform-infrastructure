$ORIGIN platform-infrastructure.com.
$TTL 60
@   IN SOA ns.platform-infrastructure.com. hostmaster.platform-infrastructure.com. (
        2026062801 ; serial
        3600       ; refresh
        900        ; retry
        604800     ; expire
        60         ; minimum
)
@   IN NS ns.platform-infrastructure.com.
@   IN A 192.168.1.164
ns  IN A 192.168.1.164
*   IN A 192.168.1.164

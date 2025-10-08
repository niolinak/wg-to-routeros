$(document).ready(function() {
    $('#convertBtn').click(function() {
        const inputConfig = $('#inputConfig').val().trim();
        const interfaceName = $('#interfaceName').val().trim() || 'wg0';
        
        if (!inputConfig) {
            alert('Please paste your WireGuard config first!');
            return;
        }

        try {
            const mikrotikConfig = convertWireGuardToMikroTik(inputConfig, interfaceName);
            $('#outputConfig').val(mikrotikConfig);
        } catch (error) {
            alert('Error converting config: ' + error.message);
            console.error(error);
        }
    });
});

function convertWireGuardToMikroTik(wgConfig, interfaceName) {
    // Parse the WireGuard config
    const config = parseWireGuardConfig(wgConfig);
    
    let output = [];
    let hasIPv6 = false;

    // Extract values from config
    const privateKey = config.Interface.PrivateKey;
    const publicKey = config.Peer.PublicKey;
    const endpoint = config.Peer.Endpoint;
    const addresses = config.Interface.Address.split(',').map(addr => addr.trim());
    const allowedIPs = config.Peer.AllowedIPs.split(',').map(ip => ip.trim());


    // Resolve endpoint hostname to IP
    const endpointHost = endpoint.split(':')[0];
    const endpointPort = endpoint.split(':')[1];
    
    // Note: In browser JavaScript, we can't directly resolve DNS, so we'll use the hostname as-is
    // In a real implementation, you might need a backend service to resolve DNS
    
    // Generate MikroTik config
    output.push(`/routing table add disabled=no fib name=${interfaceName}`);
    output.push(`/interface wireguard add listen-port=13231 mtu=1280 name=${interfaceName} private-key="${privateKey}"`);
    output.push(`/interface wireguard peers add allowed-address=${config.Peer.AllowedIPs} endpoint-address=${endpointHost} endpoint-port=${endpointPort} interface=${interfaceName} public-key="${publicKey}"`);

    // Add IP addresses
    addresses.forEach(ip => {
        const ipParts = ip.split('/');
        const ipAddr = ipParts[0];
        const isIPv6 = ipAddr.includes(':');
        
        if (isIPv6) {
            hasIPv6 = true;
            output.push(`/ipv6 address add address=${ip} advertise=no interface=${interfaceName}`);
        } else {
            const network = ipAddr.split('.').slice(0, 3).join('.') + '.0';
            output.push(`/ip address add address=${ip} interface=${interfaceName} network=${network}`);
        }
    });

    // IPv4 rules
    output.push(`/ip firewall nat add action=masquerade chain=srcnat out-interface=${interfaceName}`);
    output.push(`/ip firewall mangle add action=mark-routing chain=prerouting dst-address-list=${interfaceName} new-routing-mark=${interfaceName} passthrough=no`);
    output.push(`/ip route add disabled=no distance=1 dst-address=0.0.0.0/0 gateway=${interfaceName} pref-src="" routing-table=${interfaceName} scope=30 suppress-hw-offload=no target-scope=10`);

    // IPv6 rules if needed
    if (hasIPv6) {
        output.push(`/ipv6 firewall nat add action=masquerade chain=srcnat out-interface=${interfaceName}`);
        output.push(`/ipv6 firewall mangle add action=mark-routing chain=prerouting dst-address-list=${interfaceName} new-routing-mark=${interfaceName} passthrough=no`);
        output.push(`/ipv6 route add disabled=no distance=1 dst-address=::/0 gateway=${interfaceName} routing-table=${interfaceName} scope=30 target-scope=10`);
    }

    // Add allowed IPs to address lists
    allowedIPs.forEach(ip => {
        const isIPv6 = ip.includes(':');
        if (isIPv6) {
            output.push(`/ipv6 firewall address-list add address=${ip} list=${interfaceName}`);
        } else {
            output.push(`/ip firewall address-list add address=${ip} list=${interfaceName}`);
        }
    });

    return output.join('\n');
}

function parseWireGuardConfig(configText) {
    const lines = configText.split('\n');
    const result = {
        Interface: {},
        Peer: {}
    };
    let currentSection = null;

    lines.forEach(line => {
        line = line.trim();
        if (!line) return;

        // Check for section headers
        const sectionMatch = line.match(/^\[(\w+)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1];
            return;
        }

        // Parse key-value pairs
        if (currentSection) {
            const kvMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
            if (kvMatch) {
                const key = kvMatch[1];
                let value = kvMatch[2].trim();
                
                // Remove comments from value
                value = value.replace(/\s*#.*$/, '').trim();
                
                // Handle values that might be in quotes
                if (value.startsWith('"') && value.endsWith('"')) {
                    value = value.slice(1, -1);
                }
                if (key in result[currentSection]) {
                    result[currentSection][key] += ", "+value;
                }else{
                    result[currentSection][key] = value;
                }
            }
        }
    });

    // Validate required fields
    if (!result.Interface.PrivateKey) throw new Error('Missing Interface.PrivateKey in config');
    if (!result.Peer.PublicKey) throw new Error('Missing Peer.PublicKey in config');
    if (!result.Peer.Endpoint) throw new Error('Missing Peer.Endpoint in config');
    if (!result.Interface.Address) throw new Error('Missing Interface.Address in config');
    if (!result.Peer.AllowedIPs) throw new Error('Missing Peer.AllowedIPs in config');

    return result;
}

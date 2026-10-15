'use strict';
// 常用端口 → 服务名（足够日常判读，未收录的显示裸端口）
const PORT_SERVICES = {
  20: 'FTP数据', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
  135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 162: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 873: 'rsync',
  993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle',
  2049: 'NFS', 2375: 'Docker', 2376: 'Docker', 3128: 'Proxy', 3260: 'iSCSI',
  3306: 'MySQL', 3389: 'RDP', 5353: 'mDNS', 5432: 'PostgreSQL', 5555: 'ADB',
  5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP', 8081: 'HTTP',
  8443: 'HTTPS', 8888: 'HTTP', 9000: '服务', 9092: 'Kafka', 9200: 'ES',
  9300: 'ES', 11211: 'Memcached', 27017: 'MongoDB', 50070: 'Hadoop',
};

function svcName(port) {
  return PORT_SERVICES[port] || '';
}

function svcLabel(port) {
  const name = svcName(port);
  return name ? `${port}(${name})` : String(port);
}

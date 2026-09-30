"""Tests for streaming log loaders and content-hash helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.ingestion.loaders import (
    RawLogDirError,
    detect_log_source,
    detect_log_source_from_line,
    hash_raw_line,
    read_log_files,
    resolve_log_source,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "logs" / "auth_sample.log"


def test_detect_log_source_ssh() -> None:
    assert detect_log_source(Path("var/log/auth.log")) == "ssh"
    assert detect_log_source(Path("secure")) == "ssh"
    assert detect_log_source(Path("sshd.log")) == "ssh"
    assert detect_log_source(Path("SSH.log")) == "ssh"
    assert detect_log_source(Path("ssh.log")) == "ssh"
    assert detect_log_source(Path("OpenSSH.log")) == "ssh"
    assert detect_log_source(Path("firewall.log")) == "firewall"
    assert detect_log_source(Path("pam.log")) == "linux_pam"
    assert detect_log_source(Path("wtmp")) == "linux_wtmp"
    assert detect_log_source(Path("btmp")) == "linux_wtmp"
    assert detect_log_source(Path("last.log")) == "linux_wtmp"
    assert detect_log_source(Path("security.evtx.txt")) == "windows_security"
    assert detect_log_source(Path("powershell.txt")) == "windows_powershell"
    assert detect_log_source(Path("windows_firewall.log")) == "windows_firewall"
    assert detect_log_source(Path("rdp.txt")) == "windows_rdp"
    assert detect_log_source(Path("audit.log")) == "linux_auditd"
    assert detect_log_source(Path("kern.log")) == "linux_kern"
    assert detect_log_source(Path("dmesg")) == "linux_dmesg"
    assert detect_log_source(Path("syslog")) == "linux_syslog"
    assert detect_log_source(Path("dpkg.log")) == "linux_package"
    assert detect_log_source(Path("system.log")) == "linux_syslog"
    assert detect_log_source(Path("system.evtx.txt")) == "windows_system"
    assert detect_log_source(Path("boot.log")) == "linux_boot"
    assert detect_log_source(Path("cron.log")) == "linux_cron"
    assert detect_log_source(Path("journalctl.txt")) == "linux_journald"
    assert detect_log_source(Path("selinux.log")) == "linux_mac"
    assert detect_log_source(Path("log_show.txt")) == "macos_unified"
    assert detect_log_source(Path("asl.log")) == "macos_asl"
    assert detect_log_source(Path("install.log")) == "macos_install"
    assert detect_log_source(Path("ldap.log")) == "ldap"
    assert detect_log_source(Path("slapd.log")) == "ldap"
    assert detect_log_source(Path("radius.log")) == "radius"
    assert detect_log_source(Path("okta.json")) == "idp"
    assert detect_log_source(Path("duo.log")) == "mfa"
    assert detect_log_source(Path("krb5kdc.log")) == "kerberos_kdc"
    assert detect_log_source(Path("vault.json")) == "vault"
    assert detect_log_source(Path("firewall.log")) == "firewall"
    assert detect_log_source(Path("pfsense.txt")) == "firewall"
    assert detect_log_source(Path("filterlog.log")) == "firewall"
    assert detect_log_source(Path("openvpn.log")) == "vpn"
    assert detect_log_source(Path("named.log")) == "dns"
    assert detect_log_source(Path("dhcpd.log")) == "dhcp"
    assert detect_log_source(Path("squid.log")) == "proxy"
    assert detect_log_source(Path("nfdump.txt")) == "netflow"
    assert detect_log_source(Path("haproxy.log")) == "load_balancer"
    assert detect_log_source(Path("ise.log")) == "nac"
    assert detect_log_source(Path("hostapd.log")) == "wireless"
    assert detect_log_source(Path("bgpd.log")) == "bgp"
    assert detect_log_source(Path("cisco.txt")) == "network_device"
    assert detect_log_source(Path("eve.json")) == "ids_ips"
    assert detect_log_source(Path("suricata.json")) == "ids_ips"
    assert detect_log_source(Path("modsec.json")) == "waf"
    assert detect_log_source(Path("waf.json")) == "waf"
    assert detect_log_source(Path("clamav.txt")) == "antivirus"
    assert detect_log_source(Path("cowrie.json")) == "honeypot"
    assert detect_log_source(Path("cuckoo.json")) == "sandbox"
    assert detect_log_source(Path("siem.txt")) == "siem"
    assert detect_log_source(Path("access.log")) == "web_access"
    assert detect_log_source(Path("error.log")) == "web_error"
    assert detect_log_source(Path("iis.log")) == "web_access"
    assert detect_log_source(Path("kong.json")) == "api_gateway"
    assert detect_log_source(Path("app_runtime.json")) == "app_runtime"
    assert detect_log_source(Path("postgres.log")) == "db_postgres"
    assert detect_log_source(Path("postgresql.log")) == "db_postgres"
    assert detect_log_source(Path("mysql.log")) == "db_mysql"
    assert detect_log_source(Path("mariadb.log")) == "db_mysql"
    assert detect_log_source(Path("slow.log")) == "db_mysql"
    assert detect_log_source(Path("errorlog")) == "db_mssql"
    assert detect_log_source(Path("mssql.txt")) == "db_mssql"
    assert detect_log_source(Path("oracle.txt")) == "db_oracle"
    assert detect_log_source(Path("alert.log")) == "db_oracle"
    assert detect_log_source(Path("mongod.log")) == "db_mongodb"
    assert detect_log_source(Path("mongodb.json")) == "db_mongodb"
    assert detect_log_source(Path("cassandra.txt")) == "db_cassandra"
    assert detect_log_source(Path("cassandra.log")) == "db_cassandra"
    assert detect_log_source(Path("redis.log")) == "db_redis"
    assert detect_log_source(Path("cloudtrail.json")) == "aws_cloudtrail"
    assert detect_log_source(Path("vpcflow.txt")) == "aws_vpcflow"
    assert detect_log_source(Path("alb.log")) == "aws_elb"
    assert detect_log_source(Path("haproxy.log")) == "load_balancer"
    assert detect_log_source(Path("rds.txt")) == "aws_rds"
    assert detect_log_source(Path("postgres.log")) == "db_postgres"
    assert detect_log_source(Path("azure_ad.json")) == "azure_ad"
    assert detect_log_source(Path("gcp_audit.json")) == "gcp_audit"
    assert detect_log_source(Path("gcp_iam.json")) == "gcp_iam"
    assert detect_log_source(Path("m365.json")) == "saas_m365"
    assert detect_log_source(Path("docker.log")) == "docker"
    assert detect_log_source(Path("k8s_audit.json")) == "k8s_audit"
    assert detect_log_source(Path("kube-apiserver.log")) == "k8s_apiserver"
    assert detect_log_source(Path("kubelet.log")) == "k8s_kubelet"
    assert detect_log_source(Path("kube-scheduler.log")) == "k8s_scheduler"
    assert detect_log_source(Path("pod.log")) == "k8s_pod"
    assert detect_log_source(Path("istio.log")) == "service_mesh"
    assert detect_log_source(Path("helm.txt")) == "helm"
    assert detect_log_source(Path("registry.json")) == "container_registry"
    assert detect_log_source(Path("smtp.txt")) == "smtp"
    assert detect_log_source(Path("mta.txt")) == "mta"
    assert detect_log_source(Path("rspamd.txt")) == "mail_gateway"
    assert detect_log_source(Path("dmarc.txt")) == "dmarc"
    assert detect_log_source(Path("collab.json")) == "collab_audit"
    assert detect_log_source(Path("jenkins.txt")) == "cicd_build"
    assert detect_log_source(Path("deploy.json")) == "cicd_deploy"
    assert detect_log_source(Path("artifact_repo.txt")) == "artifact_repo"
    assert detect_log_source(Path("vcs_audit.txt")) == "vcs_audit"
    assert detect_log_source(Path("package_resolve.txt")) == "package_resolve"
    assert detect_log_source(Path("image_scan.json")) == "image_scan"
    assert detect_log_source(Path("kafka.txt")) == "kafka"
    assert detect_log_source(Path("rabbitmq.txt")) == "rabbitmq"
    assert detect_log_source(Path("esb.json")) == "esb"
    assert detect_log_source(Path("monitor.log")) == "cache"
    assert detect_log_source(Path("memcached.txt")) == "cache"
    assert detect_log_source(Path("airflow.txt")) == "airflow"
    assert detect_log_source(Path("esxi.txt")) == "hypervisor"
    assert detect_log_source(Path("hyperv.txt")) == "hypervisor"
    assert detect_log_source(Path("kvm.txt")) == "hypervisor"
    assert detect_log_source(Path("san.txt")) == "san"
    assert detect_log_source(Path("veeam.txt")) == "backup"
    assert detect_log_source(Path("ntp.txt")) == "ntp"
    assert detect_log_source(Path("license.txt")) == "license"
    assert detect_log_source(Path("ansible.txt")) == "config_mgmt"
    assert detect_log_source(Path("terraform.txt")) == "iac"
    assert detect_log_source(Path("badge.csv")) == "badge"
    assert detect_log_source(Path("cctv.json")) == "cctv"
    assert detect_log_source(Path("bms.txt")) == "bms"
    assert detect_log_source(Path("iot.json")) == "iot"
    assert detect_log_source(Path("ics.txt")) == "ics"
    assert detect_log_source(Path("voip.txt")) == "voip"
    assert detect_log_source(Path("pbx.csv")) == "pbx"
    assert detect_log_source(Path("video_conf.json")) == "video_conf"
    assert detect_log_source(Path("ivr.json")) == "ivr"
    assert detect_log_source(Path("pki_ca.json")) == "pki_ca"
    assert detect_log_source(Path("hsm.txt")) == "hsm"
    assert detect_log_source(Path("tls.txt")) == "tls"
    assert detect_log_source(Path("ct_log.json")) == "ct_log"
    assert detect_log_source(Path("code_signing.json")) == "code_signing"
    assert detect_log_source(Path("redis.log")) == "db_redis"
    assert detect_log_source(Path("audit.log")) == "linux_auditd"
    assert detect_log_source(Path("access.log")) == "web_access"
    assert detect_log_source(Path("squid.log")) == "proxy"
    assert detect_log_source(Path("system.log")) == "linux_syslog"
    assert detect_log_source(Path("error.log")) == "web_error"


def test_detect_log_source_from_line() -> None:
    ssh_line = (
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2"
    )
    assert detect_log_source_from_line(ssh_line) == "ssh"
    assert (
        detect_log_source_from_line("Dec 10 06:55:46 LabSZ Invalid user x from 1.1.1.1")
        == "ssh"
    )
    assert detect_log_source_from_line("ALLOW tcp 10.0.0.1 -> 10.0.0.2") is None
    assert detect_log_source_from_line("session opened for user alice") is None
    assert (
        detect_log_source_from_line(
            "Jan 15 10:04:00 hostname sshd[1234]: session opened for user alice"
        )
        == "ssh"
    )
    sudo_pam = (
        "Jan 15 10:15:01 testhost sudo: pam_unix(sudo:session): "
        "session opened for user root by alice(uid=1000)"
    )
    assert detect_log_source_from_line(sudo_pam) == "linux_pam"
    sudo_cmd = (
        "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls"
    )
    assert detect_log_source_from_line(sudo_cmd) == "linux_auth"
    sshd_pam = (
        "Jan 15 10:21:00 testhost sshd[99]: pam_unix(sshd:auth): "
        "authentication failure; user=root"
    )
    assert detect_log_source_from_line(sshd_pam) == "ssh"
    last_line = "alice    pts/0        192.168.1.10    Sun Aug 16 10:00   still logged in"
    assert detect_log_source_from_line(last_line) == "linux_wtmp"
    assert detect_log_source_from_line("Connection closed by 1.2.3.4") == "ssh"
    assert (
        detect_log_source_from_line("Did not receive identification string from 1.2.3.4")
        == "ssh"
    )
    assert detect_log_source_from_line("POSSIBLE BREAK-IN ATTEMPT!") == "ssh"
    win_line = (
        "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
        "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
    )
    assert detect_log_source_from_line(win_line) == "windows_security"
    assert detect_log_source_from_line("ALLOW tcp 10.0.0.1 -> 10.0.0.2") is None
    syslog_line = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
    assert detect_log_source_from_line(syslog_line) == "linux_syslog"
    audit_line = (
        'type=USER_AUTH msg=audit(1705312801.123:456): pid=1 uid=0 auid=1000 '
        'acct="alice" success=yes'
    )
    assert detect_log_source_from_line(audit_line) == "linux_auditd"
    slapd = (
        'Jan 15 10:00:01 ldap1 slapd[123]: conn=1 op=0 BIND '
        'dn="uid=alice,ou=people,dc=example,dc=com" method=128'
    )
    assert detect_log_source_from_line(slapd) == "ldap"
    okta = (
        '{"uuid":"a1","published":"2024-01-15T10:00:01.000Z",'
        '"eventType":"user.session.start",'
        '"actor":{"alternateId":"alice@example.com"},'
        '"outcome":{"result":"SUCCESS"}}'
    )
    assert detect_log_source_from_line(okta) == "idp"
    pfsense = (
        "Jan 15 10:00:01 fw1 filterlog[219]: 5,,,1000000103,em0,match,block,in,4,"
        "0x0,,64,0,0,none,6,tcp,40,10.0.0.8,1.2.3.4,54321,22,0,S,111,,65535,,"
    )
    assert detect_log_source_from_line(pfsense) == "firewall"
    cisco = (
        "Jan 15 10:00:01 router1 101: %LINEPROTO-5-UPDOWN: Line protocol on "
        "Interface GigabitEthernet0/1, changed state to down"
    )
    assert detect_log_source_from_line(cisco) == "network_device"
    squid = (
        "1705312801.123    312 10.0.0.8 TCP_MISS/200 1234 GET http://example.com/ "
        "alice HIER_DIRECT/1.2.3.4 text/html"
    )
    assert detect_log_source_from_line(squid) == "proxy"
    eve = (
        '{"timestamp":"2024-01-15T10:00:01.000000+0000","event_type":"alert",'
        '"src_ip":"10.0.0.8","dest_ip":"1.2.3.4",'
        '"alert":{"action":"blocked","severity":1}}'
    )
    assert detect_log_source_from_line(eve) == "ids_ips"
    clam = "Jan 15 10:00:01 scanhost clamd[221]: /tmp/eicar.com: Eicar-Test-Signature FOUND"
    assert detect_log_source_from_line(clam) == "antivirus"
    combined = (
        '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234'
    )
    assert detect_log_source_from_line(combined) == "web_access"
    postgres = (
        "2024-01-15 10:00:01.123 UTC [12345] alice@appdb LOG:  statement: SELECT 1"
    )
    assert detect_log_source_from_line(postgres) == "db_postgres"
    mongo = (
        '{"t":{"$date":"2024-01-15T10:00:01.000Z"},"s":"I","c":"NETWORK","id":22943,'
        '"ctx":"listener","msg":"Connection accepted"}'
    )
    assert detect_log_source_from_line(mongo) == "db_mongodb"
    redis = "12345:M 15 Jan 2024 10:00:01.123 * Ready to accept connections"
    assert detect_log_source_from_line(redis) == "db_redis"
    mysql = "2024-01-15T10:00:01.123456Z 8 Query SELECT 1 FROM t"
    assert detect_log_source_from_line(mysql) == "db_mysql"
    trail = (
        '{"eventVersion":"1.09","eventTime":"2024-01-15T10:00:01Z",'
        '"eventSource":"iam.amazonaws.com","eventName":"ConsoleLogin",'
        '"userIdentity":{"type":"IAMUser","userName":"alice"},'
        '"sourceIPAddress":"10.0.0.8"}'
    )
    assert detect_log_source_from_line(trail) == "aws_cloudtrail"
    alb = (
        "h2 2024-01-15T10:00:01.000000Z app/my-loadbalancer/50dc "
        "192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366"
    )
    assert detect_log_source_from_line(alb) == "aws_elb"
    rds = "2024-01-15 10:00:01 UTC:10.0.1.5(54321):alice@appdb:[12345]:LOG: statement: SELECT 1"
    assert detect_log_source_from_line(rds) == "aws_rds"
    dockerd = (
        'Jan 15 10:00:01 worker1 dockerd[1200]: time="2024-01-15T10:00:01Z" '
        'level=info msg="starting container"'
    )
    assert detect_log_source_from_line(dockerd) == "docker"
    audit = (
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get",'
        '"user":{"username":"alice"},"sourceIPs":["10.0.0.8"]}'
    )
    assert detect_log_source_from_line(audit) == "k8s_audit"
    cri = "2024-01-15T10:00:01.123456789Z stdout F starting nginx"
    assert detect_log_source_from_line(cri) == "k8s_pod"
    istio = (
        '[2024-01-15T10:00:01.123Z] "GET /productpage HTTP/1.1" 200 - 0 529 4 3 "-" '
        '"curl/7.68.0" "uuid" "host" "10.0.0.2:9080" '
        "outbound|9080||productpage.default.svc.cluster.local"
    )
    assert detect_log_source_from_line(istio) == "service_mesh"
    registry = (
        '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] '
        '"GET /v2/library/nginx/manifests/latest HTTP/1.1" 200 1234'
    )
    assert detect_log_source_from_line(registry) == "container_registry"
    smtpd = "Jan 15 10:00:01 mail postfix/smtpd[1234]: connect from unknown[203.0.113.10]"
    assert detect_log_source_from_line(smtpd) == "smtp"
    qmgr = (
        "Jan 15 10:00:01 mail postfix/qmgr[99]: 4F8A3: from=<alice@example.com>, "
        "size=1234, nrcpt=1 (queue active)"
    )
    assert detect_log_source_from_line(qmgr) == "mta"
    collab = (
        '{"platform":"slack","actor":"alice","action":"file_share",'
        '"workspace":"T123","ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(collab) == "collab_audit"
    jenkins = "Started by user alice"
    assert detect_log_source_from_line(jenkins) == "cicd_build"
    gha = "##[group]Run tests"
    assert detect_log_source_from_line(gha) == "cicd_build"
    gitlab_job = (
        '{"job_id":101,"pipeline_id":10,"project":"app","user":"alice",'
        '"job_name":"test","ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(gitlab_job) == "cicd_build"
    circle = "====>> Spin up environment"
    assert detect_log_source_from_line(circle) == "cicd_build"
    nexus = (
        '10.0.0.8 - alice [15/Jan/2024:10:00:01 +0000] '
        '"GET /repository/maven-releases/com/example/app/1.0.jar HTTP/1.1" 200 1234'
    )
    assert detect_log_source_from_line(nexus) == "artifact_repo"
    vcs = (
        "Jan 15 10:00:01 gitserver git-shell[99]: user alice received-pack "
        "'app.git' from 10.0.0.8"
    )
    assert detect_log_source_from_line(vcs) == "vcs_audit"
    npm = "npm http fetch GET 200 https://registry.npmjs.org/lodash 123ms"
    assert detect_log_source_from_line(npm) == "package_resolve"
    trivy = (
        '{"SchemaVersion":2,"ArtifactName":"nginx:1.25",'
        '"Results":[{"Target":"nginx:1.25","Vulnerabilities":'
        '[{"VulnerabilityID":"CVE-2024-1","Severity":"HIGH"}]}]}'
    )
    assert detect_log_source_from_line(trivy) == "image_scan"
    deploy = (
        '{"event":"deploy","service":"web","user":"alice",'
        '"environment":"prod","ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(deploy) == "cicd_deploy"
    kafka = (
        "[2024-01-15 10:00:01,123] INFO [KafkaServer id=0] started "
        "(kafka.server.KafkaServer)"
    )
    assert detect_log_source_from_line(kafka) == "kafka"
    rabbit = (
        "2024-01-15 10:00:01.123 [info] <0.123.0> connection <0.456.0> "
        "(10.0.0.8:54321 -> 10.0.0.1:5672): user 'alice' authenticated "
        "and granted access to vhost '/'"
    )
    assert detect_log_source_from_line(rabbit) == "rabbitmq"
    esb = '{"tx_id":"tx-1","route":"/orders","user":"alice","ts":"2024-01-15T10:00:01Z"}'
    assert detect_log_source_from_line(esb) == "esb"
    airflow = (
        "[2024-01-15 10:00:01,123] {taskinstance.py:1159} INFO - DAG: etl_daily Task: extract"
    )
    assert detect_log_source_from_line(airflow) == "airflow"
    memcached = "<10 get session:alice"
    assert detect_log_source_from_line(memcached) == "cache"
    esxi = "2024-01-15T10:00:01.123Z Hostd: [info] vm=web01 powered on host=esxi01"
    assert detect_log_source_from_line(esxi) == "hypervisor"
    libvirt = "Jan 15 10:00:01 kvmhost libvirtd[1234]: Domain 'web01' started"
    assert detect_log_source_from_line(libvirt) == "hypervisor"
    ntp = "Jan 15 10:00:01 ntp1 ntpd[99]: synchronized to 10.0.0.1"
    assert detect_log_source_from_line(ntp) == "ntp"
    terraform = (
        "2024-01-15T10:00:03Z Apply complete! Resources: 1 added, 0 changed, 0 destroyed."
    )
    assert detect_log_source_from_line(terraform) == "iac"
    ansible = "PLAY RECAP *********************************************************************"
    assert detect_log_source_from_line(ansible) == "config_mgmt"
    badge = "2024-01-15T10:00:01Z,B-1001,door-lobby,allow"
    assert detect_log_source_from_line(badge) == "badge"
    cctv = '{"camera_id":"cam-lobby","event":"motion","ts":"2024-01-15T10:00:01Z"}'
    assert detect_log_source_from_line(cctv) == "cctv"
    iot = (
        '{"device_id":"sensor-01","fw_version":"1.2.0","event":"telemetry",'
        '"ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(iot) == "iot"
    ics = "Jan 15 10:00:01 scada1 icsd[9]: plc=PLC01 tag=TI101 value=72.5"
    assert detect_log_source_from_line(ics) == "ics"
    voip = (
        "Jan 15 10:00:01 sip1 kamailio[9]: REGISTER sip:alice@example.com "
        "from 203.0.113.10 - 401 Unauthorized"
    )
    assert detect_log_source_from_line(voip) == "voip"
    video = (
        '{"meeting_id":"m-1001","organizer":"alice","join":true,'
        '"ip":"203.0.113.10","ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(video) == "video_conf"
    ivr = '{"call_id":"c-1001","menu":"billing","agent":"alice","ts":"2024-01-15T10:00:01Z"}'
    assert detect_log_source_from_line(ivr) == "ivr"
    pki_ca = (
        '{"cn":"web.example.com","action":"issued","user":"alice",'
        '"ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(pki_ca) == "pki_ca"
    tls = "Jan 15 10:00:01 web1 nginx[12]: ssl_handshake TLSv1.3 from 10.0.0.8"
    assert detect_log_source_from_line(tls) == "tls"
    ct = (
        '{"domain":"web.example.com","issuer":"Lets Encrypt","event":"seen",'
        '"ts":"2024-01-15T10:00:01Z"}'
    )
    assert detect_log_source_from_line(ct) == "ct_log"


def test_resolve_log_source_content_first() -> None:
    line = (
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2"
    )
    assert resolve_log_source(Path("server1.log"), line) == "ssh"
    assert resolve_log_source(Path("firewall.log"), "ALLOW tcp any") == "firewall"
    # Filename fallback when content has no SSH markers
    assert resolve_log_source(Path("SSH.log"), "kernel: boot complete") == "ssh"
    sudo_cmd = (
        "Jan 15 10:15:01 testhost sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls"
    )
    assert resolve_log_source(Path("auth.log"), sudo_cmd) == "linux_auth"
    sshd_in_auth = (
        "Jan 15 10:00:01 testhost sshd[1]: Failed password for alice from 1.2.3.4"
    )
    assert resolve_log_source(Path("auth.log"), sshd_in_auth) == "ssh"
    win_line = (
        "TimeCreated=2024-01-15T10:00:01.000Z EventID=4624 LogName=Security "
        "Computer=WIN-DC01 TargetUserName=alice IpAddress=10.0.0.8 LogonType=2"
    )
    assert resolve_log_source(Path("server1.log"), win_line) == "windows_security"
    assert resolve_log_source(Path("firewall.log"), "ALLOW tcp any") == "firewall"
    syslog_line = "Jan 15 10:00:01 testhost rsyslogd[123]: rsyslogd was HUPed"
    assert resolve_log_source(Path("system.log"), syslog_line) == "linux_syslog"
    assert resolve_log_source(Path("system.log"), "no markers here") == "linux_syslog"


def test_read_log_files_streams_fixture(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    target = raw_dir / "auth.log"
    target.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    (raw_dir / ".gitkeep").write_text("", encoding="utf-8")

    config = {"paths": {"raw_log_dir": str(raw_dir)}}
    lines = list(read_log_files(config))

    assert len(lines) > 0
    sources = {line.log_source for line in lines}
    assert "ssh" in sources
    assert "linux_kern" in sources
    assert "linux_cron" in sources
    assert all(line.content_hash for line in lines)
    assert isinstance(lines[0].raw_line, str)


def test_read_generic_filename_with_ssh_content(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    content = (
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2\n"
    )
    (raw_dir / "server1.log").write_text(content, encoding="utf-8")
    lines = list(read_log_files({"paths": {"raw_log_dir": str(raw_dir)}}))
    assert len(lines) == 1
    assert lines[0].log_source == "ssh"


def test_content_hash_stable_and_dedup_key() -> None:
    line = "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2"
    assert hash_raw_line(line) == hash_raw_line(line)
    assert hash_raw_line(line) != hash_raw_line(line + "x")


def test_duplicate_lines_share_hash(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    content = (
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2\n"
        "Jan 15 10:00:01 host sshd[1]: Failed password for alice from 1.2.3.4 port 1 ssh2\n"
    )
    (raw_dir / "auth.log").write_text(content, encoding="utf-8")
    lines = list(read_log_files({"paths": {"raw_log_dir": str(raw_dir)}}))
    assert len(lines) == 2
    assert lines[0].content_hash == lines[1].content_hash


def test_missing_raw_dir_raises(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(RawLogDirError):
        list(read_log_files({"paths": {"raw_log_dir": str(missing)}}))


def test_latin1_fallback(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    bad = b"Jan 15 10:00:01 host sshd[1]: Failed password for caf\xe9 from 1.2.3.4 port 1 ssh2\n"
    (raw_dir / "auth.log").write_bytes(bad)
    lines = list(read_log_files({"paths": {"raw_log_dir": str(raw_dir)}}))
    assert len(lines) == 1
    assert "caf" in lines[0].raw_line

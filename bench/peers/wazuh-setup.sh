#!/usr/bin/env bash
# Provision Wazuh on a disposable target for the parity run (spec §5). Installs the
# standalone Wazuh MANAGER (it writes /var/ossec/logs/alerts/alerts.json — the peer
# alert log the harness scores by ATT&CK technique via `rule.mitre.id`) and turns on
# the detection surfaces a default HIDS uses for our atomics:
#   - FIM (syscheck) in REALTIME on the dirs the file atomics touch;
#   - auditd execve monitoring so process execs reach Wazuh's audit decoder.
#
# Fairness (spec §5): the STOCK community ruleset + decoders are used unchanged; we
# only enable the standard monitors and pin the version. Wazuh does not do
# syscall-level network correlation, so a low score on the eBPF-style cases is the
# honest measurement of a log/FIM-based HIDS vs an eBPF agent — not a mis-config.
set -eu
export DEBIAN_FRONTEND=noninteractive

echo "=== install wazuh-manager (4.x apt repo) + auditd ==="
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
# The Wazuh apt repo path is the literal "4.x" (a major-line channel), NOT a
# specific minor like 4.9 — the latter 403s.
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq
apt-get install -y -qq wazuh-manager auditd >/dev/null

CONF=/var/ossec/etc/ossec.conf

# Realtime FIM on the dirs our atomics write to (defaults are periodic, not realtime,
# and omit /tmp). Insert a syscheck block just after <syscheck> opens.
python3 - "$CONF" <<'PY'
import sys, re
p = sys.argv[1]; s = open(p).read()
block = """
    <directories realtime="yes" check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin</directories>
    <directories realtime="yes" check_all="yes">/etc,/etc/cron.d,/etc/systemd/system,/etc/ssh</directories>
    <directories realtime="yes" check_all="yes">/tmp</directories>"""
if "<directories realtime=\"yes\" check_all=\"yes\">/tmp</directories>" not in s:
    s = s.replace("<syscheck>", "<syscheck>" + block, 1)
open(p, "w").write(s)
print("syscheck realtime dirs added")
PY

echo "=== auditd execve rule (process-exec surface for Wazuh's audit decoder) ==="
auditctl -D 2>/dev/null || true
auditctl -a exit,always -F arch=b64 -S execve -k audit-wazuh-c 2>/dev/null || true
auditctl -a exit,always -F arch=b32 -S execve -k audit-wazuh-c 2>/dev/null || true
# Point Wazuh at the audit log so those events are decoded + rule-matched.
if ! grep -q "audit/audit.log" "$CONF"; then
  python3 - "$CONF" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
loc = """
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
"""
s = s.replace("</ossec_config>", loc + "</ossec_config>", 1)
open(p, "w").write(s)
print("audit localfile added")
PY
fi

systemctl restart auditd 2>/dev/null || service auditd restart || true
systemctl restart wazuh-manager
sleep 8
echo -n "wazuh-manager: "; systemctl is-active wazuh-manager || true
echo -n "alerts file: "; ls -l /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "(not yet created — appears on first alert)"

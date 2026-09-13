# config/ — Konfigurasi SOAR-critical (ter-version-control)

Folder ini menyimpan salinan **sumber kebenaran** untuk konfigurasi penting yang,
karena letaknya di dalam `wazuh-docker/` (repo upstream yang **di-gitignore**),
tidak ikut ter-version-control. Tujuannya **reproducibility** — repo bisa di-clone
ulang dan dibangun kembali tanpa kehilangan kustomisasi SOAR.

## `wazuh/wazuh_manager.conf`

Template `ossec.conf` manager Wazuh. Isi kustom penting:

- **Integrasi `custom-n8n`** → webhook `/wazuh-alert` (malware) & `/wazuh-phishing` (phishing).
- **Active Response `quarantine-file`** (`rules_id 999999`) — karantina file malware.
- **Active Response `block-domain`** (`rules_id 999998`) — sinkhole domain phishing.

Wazuh manager (Docker) menyalin file ini dari bind-mount
`/wazuh-config-mount/etc/ossec.conf` ke `/var/ossec/etc/ossec.conf` **setiap kali
container start**. Karena itu registrasi AR harus ada DI SINI agar **persist** —
edit runtime di dalam container akan tertimpa saat restart.

### Cara menerapkan setelah clone / setelah edit

```bash
bash scripts/sync-wazuh-config.sh
cd wazuh-docker/single-node && docker compose up -d --force-recreate wazuh.manager
```

Lalu verifikasi:

```bash
docker exec single-node-wazuh.manager-1 grep -E 'block-domain|quarantine' /var/ossec/etc/shared/ar.conf
# harus memuat: quarantine-file0 dan block-domain0
```

> Binary Active Response (`scripts/quarantine-file`, `scripts/block-domain`) dipasang
> ke agent lewat `scripts/deploy-ar-agent.sh` / `scripts/deploy-block-domain.sh`.
> File ini hanya untuk **registrasi command di manager** (yang tadinya hilang tiap restart).

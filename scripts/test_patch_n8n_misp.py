#!/usr/bin/env python3
"""Unit test patch MISP n8n (offline). Jalankan: python3 scripts/test_patch_n8n_misp.py"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load():
    spec = importlib.util.spec_from_file_location("pnm", os.path.join(HERE, "patch-n8n-misp.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


P = load()
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


# jsCode v2 minimal (punya semua pola yang ditarget patch MISP)
JS_V2 = (
    "const mb = $input.first().json;\n"
    "const cacheNode = $('Cek Cache VT').first().json;\n"
    "const cache_hit = !!cacheNode.cache_hit;\n"
    "const mb_known = false;\n"
    "const mb_malicious = false;\n"
    "const mb_threat = mb_known && mb_malicious;\n"
    "const out = {};\n"
    "if (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5)) {\n"
    "  sev = 'CRITICAL';\n"
    "} else if (!is_system_file && (otx_threat || mb_threat || malicious >= 5 || ruleLevel >= 7)) {\n"
    "  sev = 'HIGH';\n"
    "}\n"
    "const fields = {\n"
    "    source: 'vt',\n"
    "    mb_query_status,\n"
    "    mb_threat\n"
    "};\n"
    "// patch:cache-mb:v2"
)


def main():
    js3, ch = P.patch_misp_js(JS_V2)
    check("v2 -> v3 terdeteksi berubah", ch is True)
    check("head: input jadi misp", "const misp = $input.first().json;" in js3)
    check("head: MB pakai referensi node", "const mb = $('MalwareBazaar Lookup').first().json;" in js3)
    check("blok misp_threat ditambahkan", "const misp_threat = misp_hit;" in js3)
    check("misp_to_ids dihitung", "const misp_to_ids =" in js3)
    check("severity HIGH menyertakan misp_threat",
          "otx_threat || mb_threat || misp_threat || malicious >= 5" in js3)
    check("output menyertakan misp_hit", "misp_hit," in js3 and "misp_sources" in js3)
    check("marker v3 ditambahkan", "// patch:misp:v1" in js3)
    check("marker v2 tetap ada (tidak dihapus)", "// patch:cache-mb:v2" in js3)

    js3b, ch2 = P.patch_misp_js(js3)
    check("idempoten: run ulang tidak berubah", ch2 is False and js3b == js3)

    try:
        P.patch_misp_js("const x = 1; // tanpa marker")
        check("gagal keras bila v2 tak ada", False)
    except SystemExit:
        check("gagal keras bila v2 tak ada", True)

    # node MISP terdefinisi benar
    check("node MISP bertipe httpRequest", P.MISP_NODE["type"] == "n8n-nodes-base.httpRequest")
    check("node MISP fail-open", P.MISP_NODE.get("onError") == "continueRegularOutput")
    check("node MISP pakai hash Ekstrak Alert",
          "Ekstrak Alert" in P.MISP_NODE["parameters"]["queryParameters"]["parameters"][0]["value"])

    print(f"\n{passed}/{passed + failed} lulus")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

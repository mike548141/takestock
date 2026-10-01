"""Grading against the bundled baseline, and the post-quantum readings."""

from __future__ import annotations

import pytest

from takestock.model import CryptoAsset
from takestock.policy import Policy, parse_cipher_suite, suite_kex_class


def tls(**kw) -> CryptoAsset:
    return CryptoAsset(name="tls", data_state="in-transit", protocol="tls",
                       host="www.example.test", port="443", **kw)


# ── TLS versions and cipher suites ──

@pytest.mark.parametrize("observed, expected", [
    ("TLS1.2", "TLSv1.2"), ("TLSv1.2", "TLSv1.2"), ("TLS 1.0", "TLSv1.0"),
    ("SSL3", "SSLv3"), ("SSLv3.0", "SSLv3"), ("SSL2.0", "SSLv2"), ("TLSv13", "TLSv1.3"),
])
def test_tls_version_spellings_normalise(observed, expected):
    assert Policy.normalise_tls_version(observed) == expected


def test_an_old_protocol_sets_a_weak_floor(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.0", "TLSv1.2"],
                         symmetric=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                         key_exchange=["x25519"]))
    assert a.verdict == "weak"
    assert "deprecated-protocol:TLSv1.0" in a.flags
    assert "weak-floor" in a.flags


def test_a_modern_endpoint_grades_strong(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.3"], symmetric=["TLS_AES_256_GCM_SHA384"],
                         key_exchange=["x25519"], signatures=["ecdsa_p384"]))
    assert a.verdict == "strong"
    assert "weak-floor" not in a.flags


def test_sslv3_is_weak_rather_than_ungraded(policy):
    assert policy.grade_tls_version("SSL3") == "weak"


@pytest.mark.parametrize("suite, kex", [
    ("TLS_RSA_WITH_AES_128_CBC_SHA", "rsa"),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ecdhe"),
    ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "dhe"),
    ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "anon"),
    ("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ecdh_static"),
    ("TLS_PSK_WITH_AES_128_GCM_SHA256", "psk"),
    ("TLS_AES_128_GCM_SHA256", "tls13"),
    ("SSL_RSA_WITH_RC4_128_MD5", "other"),
])
def test_suite_key_exchange_class(suite, kex):
    assert suite_kex_class(suite) == kex


def test_suite_parser_splits_cipher_mode_and_mac():
    p = parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384")
    assert (p["kex"], p["auth"], p["cipher"], p["mode"], p["mac"], p["prf"], p["bits"]) == \
        ("ecdhe", "rsa", "aes_cbc", "cbc", "sha384", "", 256)
    g = parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert (g["mac"], g["prf"]) == ("", "sha256")      # AEAD: the hash is the PRF, not a MAC
    e = parse_cipher_suite("TLS_RSA_EXPORT_WITH_RC4_40_MD5")
    assert e["export"] and e["cipher"] == "rc4" and e["bits"] == 40


def test_static_rsa_has_no_forward_secrecy_and_is_weak(policy):
    verdict, flags = policy.grade_cipher_suite("TLS_RSA_WITH_AES_128_GCM_SHA256")
    assert verdict == "weak"
    assert "no-forward-secrecy" in flags


def test_ephemeral_suite_without_a_group_is_acceptable_and_says_so(policy):
    verdict, flags = policy.grade_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert verdict == "acceptable"
    assert "not-measured:key-exchange-group" in flags


def test_ephemeral_suite_with_an_observed_group_defers_to_the_group(policy):
    verdict, flags = policy.grade_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                               groups_observed=True)
    assert verdict == "strong"
    assert "not-measured:key-exchange-group" not in flags
    a = policy.apply(tls(protocol_versions=["TLSv1.2"], key_exchange=["dh_1024"],
                         symmetric=["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]))
    assert a.verdict == "weak"       # a weak group never inherits the suite's grade
    assert "weak-dh" in a.flags


@pytest.mark.parametrize("suite, flag", [
    ("TLS_DH_anon_WITH_AES_128_CBC_SHA", "anonymous-kex"),
    ("TLS_RSA_WITH_NULL_SHA256", "null-cipher"),
    ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "export-grade"),
    ("TLS_RSA_WITH_AES_128_CBC_SHA", "cbc-mode"),
    ("TLS_RSA_WITH_AES_128_CBC_SHA", "sha1-mac"),
])
def test_suite_hazards_are_flagged(policy, suite, flag):
    verdict, flags = policy.grade_cipher_suite(suite)
    assert verdict == "weak"
    assert flag in flags


# ── SSH, IKE and SMB ──

def ssh(**extra) -> CryptoAsset:
    return CryptoAsset(name="ssh", data_state="in-transit", protocol="ssh",
                       host="bastion.example.test", port="22", extra=extra)


def test_ssh_weak_algorithms_set_the_floor(policy):
    a = policy.apply(ssh(ssh_hostkey=["ssh-rsa"], ssh_kex=["diffie-hellman-group1-sha1"],
                         ssh_mac=["hmac-md5"]))
    assert a.verdict == "weak"
    assert {"weak-hostkey:ssh-rsa", "weak-ssh-kex:diffie-hellman-group1-sha1",
            "weak-ssh-mac:hmac-md5"} <= set(a.flags)


def test_ssh_modern_algorithms_grade_strong(policy):
    a = policy.apply(ssh(ssh_hostkey=["ssh-ed25519"], ssh_kex=["curve25519-sha256"],
                         ssh_mac=["hmac-sha2-256-etm@openssh.com"]))
    assert a.verdict == "strong"


def test_ssh_ciphers_use_the_ssh_table(policy):
    a = ssh()
    a.symmetric = ["3des-cbc", "aes256-ctr"]
    policy.apply(a)
    assert a.verdict == "weak"
    assert "weak-symmetric:3des-cbc" in a.flags
    assert "ssh_cipher/aes256-ctr" in a.citations


def test_ssh_lists_on_a_non_ssh_row_are_ignored(policy):
    a = tls(protocol_versions=["TLSv1.3"], extra={"ssh_mac": ["hmac-md5"]})
    policy.apply(a)
    assert a.verdict == "strong"


def ike(**extra) -> CryptoAsset:
    return CryptoAsset(name="ike", data_state="in-transit", protocol="ike",
                       host="192.0.2.10", port="500", extra=extra)


def test_ike_group_2_is_weak_and_named(policy):
    a = policy.apply(ike(ike_dh_groups=["Group 2"]))
    assert a.verdict == "weak"
    assert "weak-dh-group:Group 2" in a.flags


def test_ike_prf_is_graded(policy):
    assert policy.apply(ike(ike_prf=["hmac-sha1"])).verdict == "weak"
    assert policy.apply(ike(ike_prf=["hmac-sha2-256"])).verdict == "strong"


def test_ike_downgrade_surface_is_flagged(policy):
    a = policy.apply(ike(ike_weakest={"group": "2"}, ike_preferred={"group": "20"},
                         ike_dh_groups=["2", "20"]))
    assert "downgrade-surface:group" in a.flags
    same = policy.apply(ike(ike_weakest={"group": "20"}, ike_preferred={"group": "20"}))
    assert not any(f.startswith("downgrade-surface") for f in same.flags)


def test_smb_dialects_are_graded_like_protocol_versions(policy):
    a = CryptoAsset(name="smb", data_state="in-transit", protocol="smb", host="files.example.test",
                    port="445", protocol_versions=["SMB1", "SMB3.1.1"])
    policy.apply(a)
    assert a.verdict == "weak"
    assert "deprecated-protocol:SMB1" in a.flags


# ── what cannot be graded ──

def test_an_unknown_token_is_surfaced_not_dropped(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.3"], symmetric=["made_up_cipher"]))
    assert a.verdict == "strong"           # the graded part still counts
    assert "ungraded:symmetric:made_up_cipher" in a.flags


def test_all_unknown_tokens_stay_unknown_never_strong(policy):
    a = ssh(ssh_mac=["hmac-example-1"], ssh_kex=["kex-example-1"])
    policy.apply(a)
    assert a.verdict == "unknown"
    assert {"ungraded:ssh_mac:hmac-example-1", "ungraded:ssh_kex:kex-example-1"} <= set(a.flags)


def test_a_policy_record_is_not_applicable(policy):
    a = CryptoAsset(name="mx", data_state="email-auth", protocol="mx", host="example.test")
    assert policy.apply(a).verdict == "n/a"


def test_a_collector_verdict_survives_when_nothing_is_gradeable(policy):
    a = CryptoAsset(name="x", data_state="at-rest", protocol="example", verdict="weak")
    assert policy.apply(a).verdict == "weak"


def test_citations_name_the_rows_that_graded(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.2"], key_exchange=["x25519"],
                         symmetric=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]))
    assert {"tls_versions/TLSv1.2", "key_exchange/x25519", "symmetric/aes128_gcm",
            "hashes/sha256"} <= set(a.citations)


def test_re_deriving_citations_never_moves_a_verdict(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.0"]))
    before = (a.verdict, list(a.flags))
    a.citations = []
    policy.annotate_citations([a])
    assert (a.verdict, a.flags) == before
    assert a.citations == ["tls_versions/TLSv1.0"]


# ── post-quantum exposure and readiness ──

def test_a_certificate_is_a_signature_finding_only(policy):
    cert = CryptoAsset(name="cert", data_state="certificate", host="www.example.test",
                       signatures=["rsa_2048"])
    policy.apply(cert)
    assert "quantum-vulnerable-signature" in cert.flags
    assert "quantum-vulnerable-kex" not in cert.flags
    assert (cert.pq_kex, cert.pq_kex_basis) == ("n/a", "no-key-establishment")
    assert (cert.pq_sig, cert.pq_sig_basis) == ("classical", "")


def test_a_tls12_suite_names_both_classical_jobs(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.2"],
                         symmetric=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]))
    assert {"quantum-vulnerable-kex", "quantum-vulnerable-signature"} <= set(a.flags)


def test_post_quantum_key_exchange_does_not_excuse_a_classical_signature(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.3"], key_exchange=["x25519mlkem768"],
                         signatures=["ecdsa_p256"]))
    assert "quantum-vulnerable-kex" not in a.flags
    assert "quantum-vulnerable-signature" in a.flags
    assert a.pq_kex == "ready"


def test_offering_both_kinds_reads_hybrid(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.3"], key_exchange=["x25519mlkem768", "x25519"]))
    assert (a.pq_kex, a.pq_kex_basis) == ("hybrid", "")


def test_an_unprobed_service_is_a_gap_of_its_own_kind(policy):
    a = CryptoAsset(name="imap", data_state="in-transit", protocol="imap", host="mail.example.test",
                    port="143", flags=["unverified-encryption:imap"])
    policy.apply(a)
    assert (a.pq_kex, a.pq_kex_basis) == ("gap", "not-probed")
    b = policy.apply(CryptoAsset(name="x", data_state="in-transit", protocol="example"))
    assert (b.pq_kex, b.pq_kex_basis) == ("gap", "not-observed")


def test_an_unread_class_is_a_gap_never_not_applicable(policy):
    a = policy.apply(CryptoAsset(name="disk", data_state="at-rest", protocol="example"))
    assert (a.pq_kex, a.pq_kex_basis) == ("gap", "not-yet-read")


def test_a_cleartext_service_has_nothing_to_migrate(policy):
    a = policy.apply(CryptoAsset(name="telnet", data_state="in-transit", protocol="telnet",
                                 host="192.0.2.20", port="23", flags=["plaintext:telnet"]))
    assert (a.pq_kex, a.pq_kex_basis) == ("n/a", "cleartext-service")


def test_every_value_has_a_basis_exactly_when_it_is_not_a_reading(policy):
    rows = [
        tls(protocol_versions=["TLSv1.3"], key_exchange=["x25519"]),
        CryptoAsset(name="mx", data_state="email-auth", protocol="mx"),
        CryptoAsset(name="disk", data_state="at-rest"),
        CryptoAsset(name="cert", data_state="certificate", signatures=["mldsa"]),
    ]
    for a in rows:
        policy.apply(a)
        for value, basis in ((a.pq_kex, a.pq_kex_basis), (a.pq_sig, a.pq_sig_basis)):
            assert bool(basis) == (value in ("gap", "n/a")), (a.name, value, basis)


def test_symmetric_margin_names_floor_and_best(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.3"],
                         symmetric=["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]))
    assert "quantum-symmetric-margin:128-256" in a.flags
    one = policy.apply(tls(protocol_versions=["TLSv1.3"], symmetric=["TLS_AES_256_GCM_SHA384"]))
    assert "quantum-symmetric-margin:256" in one.flags


def test_an_unrated_cipher_reports_no_margin(policy):
    assert policy.symmetric_strength("chacha20_poly1305") == 0
    assert policy.symmetric_strength("3des-cbc") == 112
    assert policy.symmetric_strength("aes256_xts") == 256


def test_re_reading_quantum_exposure_leaves_everything_else_alone(policy):
    a = policy.apply(tls(protocol_versions=["TLSv1.0"], signatures=["rsa_2048"]))
    a.flags = [f for f in a.flags if not f.startswith("quantum-")] + ["quantum-stale-example"]
    verdict = a.verdict
    policy.annotate_quantum_exposure([a])
    assert a.verdict == verdict
    assert "quantum-stale-example" not in a.flags
    assert "quantum-vulnerable-signature" in a.flags
    assert "deprecated-protocol:TLSv1.0" in a.flags

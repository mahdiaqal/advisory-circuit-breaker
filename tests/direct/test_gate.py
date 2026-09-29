import json


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><parent><groupId>org.apache.logging.log4j</groupId><artifactId>log4j</artifactId><version>2.14.1</version></parent><artifactId>log4j-core</artifactId></project>"""
ADVISORY = {"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "summary": "Remote code injection in Log4j",
            "description": "An attacker can execute arbitrary code remotely through JNDI lookups.",
            "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                                 "vulnerable_version_range": ">= 2.13.0, < 2.15.0"}]}


def register(contract, vm, owner, version="2.14.1"):
    vm.sender = owner
    contract.register_release("log4j-gate", "org.apache.logging.log4j", "log4j-core", version,
                              "GHSA-jfh8-c2jp-5v3q", "RCE,DOS", 3600)


def sources(vm, pom=POM, advisory=ADVISORY):
    vm.mock_web(r".*repo\.maven\.apache\.org/.*\.pom", {"status": 200, "body": pom})
    vm.mock_web(r".*api\.github\.com/advisories/.*", {"status": 200, "body": json.dumps(advisory)})


def test_rce_quarantines_and_blocks_use(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy("contracts/AdvisoryCircuitBreaker.py")
    register(c, direct_vm, direct_alice)
    sources(direct_vm)
    direct_vm.mock_llm(r"(?s).*Classify the PRIMARY.*", json.dumps({"impact": "RCE"}))
    c.scan_advisory("log4j-gate", "scan-1")
    gate = json.loads(c.get_gate("log4j-gate"))
    report = json.loads(c.get_scan("log4j-gate", "scan-1"))
    assert gate["status"] == "BLOCKED" and not c.can_use("log4j-gate")
    assert report["affected"] is True and report["impact"] == "RCE"
    assert report["coordinates_ok"] and report["record_ok"]
    with direct_vm.expect_revert("fresh permissive scan required"):
        c.activate("log4j-gate")
    with direct_vm.expect_revert("active fresh permissive gate required"):
        c.record_use("log4j-gate", "operation-1")
    with direct_vm.expect_revert("unique scan ID"):
        c.scan_advisory("log4j-gate", "scan-1")


def test_unaffected_release_activates_once_and_records_use(direct_vm, direct_deploy,
                                                            direct_alice, direct_bob):
    c = direct_deploy("contracts/AdvisoryCircuitBreaker.py")
    register(c, direct_vm, direct_alice, "2.17.1")
    sources(direct_vm, pom=POM.replace("2.14.1", "2.17.1"))
    c.scan_advisory("log4j-gate", "scan-1")
    assert json.loads(c.get_gate("log4j-gate"))["status"] == "OPEN"
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("gate owner required"):
        c.activate("log4j-gate")
    c.activate("log4j-gate")
    assert c.can_use("log4j-gate")
    c.record_use("log4j-gate", "operation-1")
    assert json.loads(c.get_use("log4j-gate", "operation-1"))["scan_root"]
    with direct_vm.expect_revert("unique use ID"):
        c.record_use("log4j-gate", "operation-1")


def test_unknown_impact_and_spoofed_pom_fail_closed(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy("contracts/AdvisoryCircuitBreaker.py")
    register(c, direct_vm, direct_alice)
    sources(direct_vm)
    direct_vm.mock_llm(r"(?s).*Classify the PRIMARY.*", json.dumps({"impact": "UNKNOWN"}))
    c.scan_advisory("log4j-gate", "unknown")
    assert json.loads(c.get_gate("log4j-gate"))["status"] == "REVIEW"
    direct_vm.clear_mocks()
    sources(direct_vm, pom=POM.replace("log4j-core", "lookalike"))
    c.scan_advisory("log4j-gate", "spoofed")
    assert json.loads(c.get_scan("log4j-gate", "spoofed"))["coordinates_ok"] is False
    assert not c.can_use("log4j-gate")


def test_stale_scan_stops_use(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy("contracts/AdvisoryCircuitBreaker.py")
    register(c, direct_vm, direct_alice, "2.17.1")
    sources(direct_vm, pom=POM.replace("2.14.1", "2.17.1"))
    c.scan_advisory("log4j-gate", "scan-1")
    c.activate("log4j-gate")
    direct_vm.warp("2030-01-01T00:00:00Z")
    from genlayer import gl
    gl.message_raw["datetime"] = "2030-01-01T00:00:00Z"
    assert not c.can_use("log4j-gate")
    with direct_vm.expect_revert("active fresh permissive gate required"):
        c.record_use("log4j-gate", "late-use")

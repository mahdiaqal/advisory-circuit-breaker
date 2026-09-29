# StudioNet proofs

Contract: [0x21B13BdC752245eafee5E6EB507bB377edd6BA9C](https://explorer-studio.genlayer.com/address/0x21B13BdC752245eafee5E6EB507bB377edd6BA9C)

Every transaction below was checked through StudioNet RPC: `status=FINALIZED` and leader `execution_result=SUCCESS`. The deployed source returned by `genlayer code` matches `contracts/AdvisoryCircuitBreaker.py` byte-for-byte after newline normalization. The earlier deployment at `0x70f9B4738EE52B1dd89Ca79CCC3CF5552795A7A5` preceded a source-header correction and is **not** the submitted deployment.

| Step | Transaction | Verified result |
| --- | --- | --- |
| Deploy matching source | [0x365895ae…](https://explorer-studio.genlayer.com/tx/0x365895ae930ead86b84b09f32c55b7af693e0b0666e65164c872186327f9432d) | Contract created |
| Register vulnerable release | [0xc9220ee1…](https://explorer-studio.genlayer.com/tx/0xc9220ee156d90568680861c5bba2a23df5a97a281069853c15b8750fbab44e06) | `log4j-core:2.14.1` against `GHSA-jfh8-c2jp-5v3q` |
| Scan vulnerable release | [0xf7117c7f…](https://explorer-studio.genlayer.com/tx/0xf7117c7f729e4eef0558093ee422bc285d260a9aa3a90dd57abe4cd62f7207b4) | Maven and advisory HTTP 200; coordinates and advisory ID match; affected `true`; impact `RCE`; decision `BLOCKED` |
| Register patched release | [0x81a41b37…](https://explorer-studio.genlayer.com/tx/0x81a41b373ec2233de0f364c57fc2903ef0cccaa7b392abc98b6bf62611cf0b31) | `log4j-core:2.17.1` against the same advisory |
| Scan patched release | [0xf0bf6edd…](https://explorer-studio.genlayer.com/tx/0xf0bf6eddb3e6f0eba47652a70913dd0e5aaf21f0b76051dfce1782b2389d3614) | Maven and advisory HTTP 200; coordinates and advisory ID match; affected `false`; decision `OPEN` for this **named advisory only** |
| Activate patched gate | [0x5a4a7b25…](https://explorer-studio.genlayer.com/tx/0x5a4a7b254ad88299b22395c5afe6df8d1714ecf6b452f3541d0bb896d6d2c7b1) | Owner-only gate activation |
| Record patched use | [0x110c50e9…](https://explorer-studio.genlayer.com/tx/0x110c50e94f7756802947823101a64b76bb903b73a4d9fed2ed1224c3f8187cda) | Immutable `release-use-1`, bound to scan root `8c6adfccad939b800b6d4a5bc8296d904cb8e9ad5542801c7d5ac3594e23a60c` |

Read-only calls after the lifecycle returned `can_use(log4j-vulnerable)=false` and `can_use(log4j-patched)=true`. The use record is an internal authorization log, not proof that an external service installed or deployed this package.

Direct tests: 4 passed. GenVM lint and SDK validation passed. The direct suite covers RCE blocking, unaffected release activation/use, unknown impact and spoofed POM fail-closed behavior, and expiration. The onchain proof specifically demonstrates the first two paths.

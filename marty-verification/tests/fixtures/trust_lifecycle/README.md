# Trust lifecycle fixtures

These synthetic public CA certificates exercise registry identity and update behavior.
`first.pem` and `renewed.pem` have the same subject but different serial numbers and keys.
`other.pem` belongs to a different subject. None contains a jurisdiction code in its subject.

The certificates were generated for these tests with in-memory P-256 keys. Private keys
were never written or retained. These certificates are not production trust anchors.

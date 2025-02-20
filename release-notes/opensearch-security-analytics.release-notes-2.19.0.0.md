## Version 2.19.0.0 2025-02-03
Compatible with OpenSearch 2.19.0

### Maintenance
* Incremented version to 2.19.0 ([#1444](https://github.com/opensearch-project/security-analytics/pull/1444))
* Fix CVE-2024-47535. ([#1460](https://github.com/opensearch-project/security-analytics/pull/1460))

### Refactoring
* optimize sigma aggregation rule based detectors execution workflow ([#1418](https://github.com/opensearch-project/security-analytics/pull/1418))
* Adding various OCSF 1.1 fields to log type static mappings ([#1403](https://github.com/opensearch-project/security-analytics/pull/1403))

### Bug Fixes
* Add validation for threat intel source config ([#1393](https://github.com/opensearch-project/security-analytics/pull/1393))
* fix detector to work for trigger conditions filtering on aggregation rules ([#1423](https://github.com/opensearch-project/security-analytics/pull/1423))
* fixes the duplicate alerts generated by Aggregation Sigma Roles ([#1424](https://github.com/opensearch-project/security-analytics/pull/1424))
* OCSF1.1 Fixes ([#1439](https://github.com/opensearch-project/security-analytics/pull/1439))
* Added catch for unexpected inputs. ([#1442](https://github.com/opensearch-project/security-analytics/pull/1442))
* Refactored flaky test. ([#1464](https://github.com/opensearch-project/security-analytics/pull/1464))

### Documentation
* Added 2.19.0 release notes. ([#1468](https://github.com/opensearch-project/security-analytics/pull/1468))
nist-data-mirror
================

An AWS Lambda to mirror the CPE/CVE XML and JSON data from NIST.

The intended purpose of nist-data-mirror is to be able to replicate the NIST vulnerabiity data 
inside a company firewall so that local (faster) access to NIST data can be achieved.

nist-data-mirror does not rely on any third-party dependencies, only the Java SE core libraries and aws-java-sdk-s3. 
It can be used in combination with [OWASP Dependency-Check] in order to provide Dependency-Check 
a mirrored copy of NIST data.

Usage
----------------

Edit serverless.yml:
 * replace "deployment-bucket-goes-here" to the name of an S3 bucket where the artifact will be uploaded for deployment with CloudFormation
 * replace "bucket-name-goes-here" with the name of an S3 bucket that's configured for "Static website hosting"

### Building

```sh
mvn clean package
```

### Deploying

```sh
npm install -g serverless
serverless deploy -v
```

Copyright & License
-------------------

nist-data-mirror is Copyright (c) Steve Springett. All Rights Reserved.

Dependency-Check is Copyright (c) Jeremy Long. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE] [Apache 2.0] file for the full license.

  [OWASP Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
  [Apache 2.0]: https://github.com/stevespringett/nist-data-mirror/blob/master/LICENSE

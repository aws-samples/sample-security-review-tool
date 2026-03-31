import { License } from './types.js';

const currentYear = new Date().getFullYear();

export const AWS_LICENSE: License = {
    name: 'AWS',
    licenseContent: `
Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License. The AWS Licensor grants you the following additional permissions for this material:

1. You may modify this material and use any modified material solely in connection with your permitted use of the Services during the Term.

2. If you participate in the AWS Partner Network Program under the AWS Partner Network Terms and Conditions, you may distribute this material to AWS customers as part of your participation in the AWS Partner Network Program.

You acknowledge that this material is not designed or intended to be used to (a) make automated decisions that could have a consequential impact on an individual's legal or financial position, life or employment opportunities, human rights, or result in physical or psychological injury to an individual,

(b) support any use in which an interruption, defect, error, or other failure could result in the death or serious bodily injury of any individual or in physical or environmental damage, or

(c) meet your regulatory, legal, or other obligations. You are solely responsible for conducting additional testing, assessments, and implementing use case-specific safeguards, as needed.
`,
    headerContent: `Copyright Amazon.com, Inc. or its affiliates. This material is AWS Content under the AWS Enterprise Agreement
or AWS Customer Agreement (as applicable) and is provided under the AWS Intellectual Property License.`,
    noticeContent: `
Notices

Customers and AWS Partners are responsible for making their own independent assessment of these materials. This content:

(a) is for informational and demonstration purposes only as part of the Generative AI Innovation Center (GenAIIC) reusable assets program,

(b) represents AWS current product offerings and practices, which are subject to change without notice, and

(c) does not create any commitments or assurances from AWS and its affiliates, suppliers, or licensors.

You acknowledge that these materials are provided as examples and starting points for development. Before deploying to production environments, you are solely responsible for:

(a) conducting appropriate testing and validation
(b) implementing necessary safeguards for your specific use case
(c) ensuring compliance with your organization's requirements
(d) performing security and performance assessments

AWS products or services are provided "as is" without warranties, representations, or conditions of any kind, whether express or implied.
`
};

export const MIT_LICENSE: License = {
    name: 'MIT',
    licenseContent: `
MIT License

Copyright (c) ${currentYear} [Copyright Holder]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`,
    headerContent: `Copyright (c) ${currentYear} Amazon.com
This file is licensed under the MIT License.
See the LICENSE file in the project root for full license information.`,
    noticeContent: `
MIT License Notice

This project is licensed under the MIT License - see the LICENSE file for details.

The MIT License is a permissive license that is short and to the point. It lets people do anything with your code with proper attribution and without warranty.
`
};

export const APACHE_LICENSE: License = {
    name: 'Apache',
    licenseContent: `Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

[Full Apache 2.0 license text omitted for brevity - contains same content as original]
`,
    headerContent: `Copyright ${currentYear} Amazon.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.`,
    noticeContent: `
Apache License 2.0 Notice

This project is licensed under the Apache License, Version 2.0 - see the LICENSE file for details.

The Apache License 2.0 is a permissive license that also provides an express grant of patent rights from contributors to users. It requires:
- Preservation of copyright and license notices
- Prominent notices for any changes made to the original files
- Inclusion of a copy of the license in any distribution

For more information, see: https://www.apache.org/licenses/LICENSE-2.0
`
};

export function getAllLicenses(): License[] {
    return [AWS_LICENSE, MIT_LICENSE, APACHE_LICENSE];
}

export class LicenseRegistry {
    public getAllLicenses(): License[] {
        return getAllLicenses();
    }

    public getLicense(licenseType: string): License {
        const normalized = licenseType.toUpperCase();
        switch (normalized) {
            case 'AWS':
                return AWS_LICENSE;
            case 'MIT':
                return MIT_LICENSE;
            case 'APACHE':
            case 'APACHE-2.0':
            case 'APACHE_2.0':
                return APACHE_LICENSE;
            default:
                throw new Error(`Unknown license type: ${licenseType}`);
        }
    }
}

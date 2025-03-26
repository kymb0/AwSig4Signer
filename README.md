# AwSig4Signer

**Burp Suite Extension for AWS Signature V4 Signing**  
**Author**: kymb0 & grok  
**Version**: 2.1  

A Burp extension for signing AWS requests with Signature V4. Supports all signing methods (Header, Presigned, Chunked) and lets you pick which tools to sign. Built for hunters testing AWS-hosted apps—automates auth so you can focus on testing.

## Key Features

- **All SigV4 Methods**: Header-based, presigned URLs, or chunked uploads—choose what fits your target.
- **Tool Control**: Sign only the Burp tools you want (Proxy, Repeater, Scanner, etc.).
- **Auto-Signing**: Signs in-scope traffic or specific regex-matched URLs.
- **Credential Extraction**: Pulls AWS keys from auth endpoint responses (JSON/XML).
- **Manual Signing**: Quick "Sign Now!" or full request editor in the tab.
- **Logging Toggle**: Enable/disable logs

## Config Fields & Examples

**Config Tab**: Set these up, save as profiles, and go.

| Field             | Purpose                          | Example Value                  |
|-------------------|----------------------------------|--------------------------------|
| **Access Key**    | AWS Access Key ID               | `AKIAIOSFODNN7EXAMPLE`        |
| **Secret Key**    | AWS Secret Access Key           | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| **Region**        | AWS region                      | `us-east-1`                   |
| **Service**       | AWS service to sign             | `iam` or `s3`                 |
| **Auth Endpoint** | URL path for creds extraction   | `/get-credentials`            |
| **Access Key Path** | JSON/XML path to Access Key   | `Credentials.AccessKeyId`     |
| **Secret Key Path** | JSON/XML path to Secret Key   | `Credentials.SecretAccessKey` |
| **URL Filter**    | Regex to limit signing          | `.*amazonaws.*`               |

**Signing Method**: Dropdown—pick one:
- `Header`: Adds `Authorization` header (e.g., IAM testing).
- `Presigned`: Query string signing (e.g., S3 URLs).
- `Chunked`: Sets streaming SHA (e.g., S3 uploads, simplified).

**Tools**: Checkboxes—enable signing for:
- Proxy, Repeater (default on), Scanner, Spider, Intruder, Sequencer.

## Usage Examples

1. **Auto-Sign Repeater (Header)**  
   - Set: Access Key=`AKIA...`, Secret Key=`wJalr...`, Region=`us-east-1`, Service=`iam`.  
   - Method: `Header`, Tools: `Repeater`, Auto-Signing: On.  
   - Send in Repeater: `POST https://iam.amazonaws.com/` → Gets `Authorization` header.

2. **Presigned URL (Manual)**  
   - Set: Same creds, Method: `Presigned`.  
   - Manual Sign tab: Paste `GET /my-bucket`, hit "Generate Signature".  
   - Output: `GET /my-bucket?X-Amz-Signature=abc123...`.

3. **Extract Creds (Scanner)**  
   - Set: Auth Endpoint=`/get-credentials`, Paths=`Credentials.*`, Auto-Extraction: On, Tools: `Scanner`.  
   - POST to endpoint → Keys auto-populate from response.

4. **Spider an AWS API**  
   - Set: Creds, Method: `Header`, Tools: `Spider`, URL Filter=`.*api.aws.*`.  
   - Spider `https://api.aws.com/` → Crawls with signed requests.

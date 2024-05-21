# AWS Lambda Layer for AWS SDK for Pandas (AWS Wrangler) 

AWS Lambda Layer for AWS SDK for Pandas (AWS Wrangler) does not exist in GovCloud and must be downloaded before deploying the CDK solution.

The latest releases can be found here: https://github.com/aws/aws-sdk-pandas/releases/latest

Download the the latest layer zip, for Python 3.11, from the repository and place in this folder before deploying the CDK:

```assets/lambda/layers/awswrangler/```

> **_NOTE:_** If you are manually downloading the layer, you will also need to update `stack/shca_stack.py` `self.aws_wrangler_layer` with the correct filename.

## Automated method for downloading and updating stack/shca_stack.py

We have provided a helper script `update_aws_wrangler.sh` for downloading the latest compatible layer.

Execute the following:

```
bash update_aws_wrangler.sh
```
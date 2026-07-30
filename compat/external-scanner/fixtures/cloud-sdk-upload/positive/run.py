import boto3
s3 = boto3.client("s3")
s3.put_object(Bucket="mybucket", Key="data.json", Body=payload)

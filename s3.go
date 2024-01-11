package goawscrudclient

import (
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

type S3Crud struct {
	s3iface.S3API
	AccountId string
}

func (c *S3Crud) ListBuckets(input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{
		Buckets: []*s3.Bucket{},
		Owner: &s3.Owner{
			ID: &c.AccountId,
		},
	}, nil
}

func (c *S3Crud) DeleteBucket(input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
  return &s3.DeleteBucketOutput{}, nil
}

func (c *S3Crud) BatchDeleteBucketObjects(bucketName *string) error {
  return nil
}

func (c *S3Crud) ListObjectsV2(input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
  return &s3.ListObjectsV2Output{
  	Contents:              []*s3.Object{},
  }, nil 
}

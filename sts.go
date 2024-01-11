package goawscrudclient

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)


type StsCrud struct {
  stsiface.STSAPI
  AccountId string
}

func (c *StsCrud) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
  return &sts.AssumeRoleOutput{
  	AssumedRoleUser:  &sts.AssumedRoleUser{
  		Arn:           aws.String("todo"),
  		AssumedRoleId: aws.String("todo"),
  	},
  	Credentials:      &sts.Credentials{
  		AccessKeyId:     aws.String("ACCESSKEY"),
  		Expiration:      aws.Time(time.Now().Add(time.Hour).UTC()),
  		SecretAccessKey: aws.String("SECRETACCESSKEY"),
  		SessionToken:    aws.String("SESSIONTOKEN"),
  	},
  	PackedPolicySize: aws.Int64(10),
  	SourceIdentity:   input.SourceIdentity,
  }, nil
}


func (c *StsCrud) GetCallerIdentity(*sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
  return &sts.GetCallerIdentityOutput{
  	Account: &c.AccountId,
  	Arn:     aws.String("todo"),
  	UserId:  aws.String("todo"),
  }, nil
}
func (c *StsCrud) GetFederationToken(*sts.GetFederationTokenInput) (*sts.GetFederationTokenOutput, error) {
  return &sts.GetFederationTokenOutput{
  	Credentials:      &sts.Credentials{},
  	FederatedUser:    &sts.FederatedUser{},
  	PackedPolicySize: new(int64),
  }, nil
}

package goawscrudclient

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
)

type Route53Crud struct {
  route53iface.Route53API
}


func (c *Route53Crud) ListHostedZones(input *route53.ListHostedZonesInput) (*route53.ListHostedZonesOutput, error) {
  return &route53.ListHostedZonesOutput{
  	HostedZones: []*route53.HostedZone{},
  	IsTruncated: aws.Bool(false),
  },nil
}
func (c *Route53Crud) DeleteHostedZone(*route53.DeleteHostedZoneInput) (*route53.DeleteHostedZoneOutput, error) {
  return &route53.DeleteHostedZoneOutput{
  	ChangeInfo: &route53.ChangeInfo{
  		Id:          aws.String("todo"),
  		Status:      aws.String("todo"),
  		SubmittedAt: aws.Time(time.Now().UTC()),
  	},
  }, nil
}
func (c *Route53Crud) ListResourceRecordSets(*route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
  return &route53.ListResourceRecordSetsOutput{
  	IsTruncated:          aws.Bool(false),
  	ResourceRecordSets:   []*route53.ResourceRecordSet{},
  }, nil
}
func (c *Route53Crud) ChangeResourceRecordSets(*route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
  return &route53.ChangeResourceRecordSetsOutput{
  	ChangeInfo: &route53.ChangeInfo{
  		Id:          aws.String("todo"),
  		Status:      aws.String("todo"),
  		SubmittedAt: aws.Time(time.Now().UTC()),
  	},
  },nil
}

package goawscrudclient

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)


func Test_CreateSubnet(t *testing.T) {
  client := Ec2Crud{
  	AccountId: "00000",
  	Region:    "eu-central-1",
  }

  cvo, err := client.CreateVpc(&ec2.CreateVpcInput{
		CidrBlock: aws.String("10.0.0.0/16"),
	})
  if err != nil {
    t.Errorf("Got an error createing vpc: %v", err)
    t.FailNow()
  }
  cso, err := client.CreateSubnet(&ec2.CreateSubnetInput{
		CidrBlock:          aws.String("10.10.0.0/24"),
		VpcId:              cvo.Vpc.VpcId,
	})
  if err != nil {
    t.Errorf("Got an error creating snet: %v", err)
    t.FailNow()
  }
  s := ec2.Subnet{}
  err = BH().Get(cso.Subnet.SubnetArn, &s)
  if err != nil {
    t.Errorf("Couldn't retrieve snet: %v", err)
    t.FailNow()
  }

  res, err := client.RunInstances(&ec2.RunInstancesInput{
  	ImageId:                           aws.String("imagebla"),
  	InstanceType:                      aws.String("type1"),
  	KeyName:                           aws.String("keyname"),
  })
  if err != nil {
    t.Errorf("Couldn't create instance: %v", err)
    t.FailNow()
  }

  _, err = client.TerminateInstances(&ec2.TerminateInstancesInput{
  	InstanceIds: []*string{res.Instances[0].InstanceId},
  })

  if err != nil {
    t.Errorf("Couldn't terminate instance: %v", err)
    t.FailNow()
  }
}

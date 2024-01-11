package goawscrudclient

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Test_CreateRole(t *testing.T) {
  client := IamCrud{
    AccountId: "000000000",
  }

  _, err := client.CreateRole(&iam.CreateRoleInput{
  	Description:              aws.String("Desc"),
  	Path:                     aws.String("/"),
  	RoleName:                 aws.String("testrole"),
  })

  if err != nil {
    t.Errorf("Error creating role: %v", err)
  }

  gro, err := client.GetRole(&iam.GetRoleInput{
  	RoleName: aws.String("testrole"),
  })

  if err != nil {
    t.Errorf("Error getting the role again: %v", err)
    t.FailNow()
  }

  t.Log(gro.Role.Arn)

}

func Test_GetUser(t *testing.T) {
  client := IamCrud{
    AccountId: "000000000",
    AccessKeyId: "accesskey",
  }

  guo, err := client.GetUser(&iam.GetUserInput{})

  if err != nil {
    t.Errorf("Error getting user: %v", err)
    t.FailNow()
  }

  t.Logf("UserREturned: %v", guo)
    
}

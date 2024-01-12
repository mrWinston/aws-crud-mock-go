package goawscrudclient

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Test_MultiAccount(t *testing.T) {
  client1 := &IamCrud{
  	AccountId:   "111111111",
  	AccessKeyId: "client1",
  }
  client2 := &IamCrud{
  	AccountId:   "222222222",
  	AccessKeyId: "client2",
  }

  _, err := client1.CreateUser(&iam.CreateUserInput{
  	UserName:            aws.String("demo"),
    Tags: []*iam.Tag{{
    	Key:   aws.String("client"),
    	Value: aws.String("1"),
    }},
  })
  if err != nil {
    t.Errorf("Failed creating user: %v", err)
    t.FailNow()
  }
  _, err = client2.CreateUser(&iam.CreateUserInput{
  	UserName:            aws.String("demo"),
    Tags: []*iam.Tag{{
    	Key:   aws.String("client"),
    	Value: aws.String("2"),
    }},
  })
  if err != nil {
    t.Errorf("Failed creating user: %v", err)
    t.FailNow()
  }
  guo1, err := client1.GetUser(&iam.GetUserInput{
  	UserName: aws.String("demo"),
  })
  if err != nil {
    t.Errorf("Failed getting user: %v", err)
    t.FailNow()
  }
  guo2, err := client2.GetUser(&iam.GetUserInput{
  	UserName: aws.String("demo"),
  })
  if err != nil {
    t.Errorf("Failed getting user: %v", err)
    t.FailNow()
  }
  
  if *guo1.User.Tags[0].Value != "1" {
    t.Errorf("User from client 1 is not correct: %v", guo1)
  }
  if *guo2.User.Tags[0].Value != "2" {
    t.Errorf("User from client 2 is not correct: %v", guo1)
  }
}

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

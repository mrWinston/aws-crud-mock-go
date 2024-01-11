package goawscrudclient

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/organizations"
)



func Test_ListTagsForResource(t *testing.T) {
  
  client := OrganizationsCrud{
    Accountid: "00000000",
  }

  cao, err := client.CreateAccount(&organizations.CreateAccountInput{
  	AccountName:            aws.String("test"),
  	Email:                  aws.String("bla@example.com"),
    Tags: []*organizations.Tag{{
    	Key:   aws.String("Tagone"),
    	Value: aws.String("valone"),
    }},
  })

  t.Errorf("accid: %s", *cao.CreateAccountStatus.AccountId)

  if err != nil {
    t.Errorf("Error creating acc: %v", err)
  }
  

  out, err := client.ListTagsForResource(&organizations.ListTagsForResourceInput{
  	ResourceId: cao.CreateAccountStatus.AccountId,
  })

  for _, t2 := range out.Tags {
    t.Errorf("Tag is: %v", t2)
  }

  t.Logf("output is : %v", out)
  t.Logf("err is : %v", err)
}
